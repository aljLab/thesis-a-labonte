package srv6proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// -----------------------------------------------------------------------------
// Configuration constants
// -----------------------------------------------------------------------------

const (
	// Interface names.
	Tun0    = "tun0"
	Tun1    = "tun1"
	VethIn  = "veth-in"
	VethOut = "veth-out"
	Decap4  = "decap4"

	// IPv4 destination prefix to encapsulate.
	TargetIPv4Net = "10.0.10.0/24"

	// SRv6 SID allocation prefix and individual SIDs.
	SIDPrefix     = "fd00::/64"
	LegacySID     = "fd00::02"
	DecapSID      = "fd00::03"

	// Routing table IDs.
	TableTun0  = 200 // iif tun0    -> veth-in
	TableVeth  = 201 // iif veth-out -> tun1
	TableTun1  = 202 // iif tun1    -> decap4 / End.DT4

	// Rule priorities.
	PriorityTun0  = 200
	PriorityVeth  = 201
	PriorityTun1  = 202

	MainTable = unix.RT_TABLE_MAIN
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP: " + s)
	}
	return ip
}

func linkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func ensureLink(link netlink.Link) error {
	name := link.Attrs().Name

	if existing, err := linkByName(name); err == nil {
		fmt.Printf("link exists: %s (%s)\n", name, existing.Type())
		return nil
	} else if !errors.Is(err, syscall.ENODEV) &&
		!errors.Is(err, syscall.ENOENT) {
		// Some netlink errors are wrapped, so only continue when the
		// interface genuinely does not exist.
		if _, retryErr := linkByName(name); retryErr == nil {
			return nil
		}
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create link %s: %w", name, err)
	}

	fmt.Printf("created link: %s\n", name)
	return nil
}

func ensureUp(name string) error {
	link, err := linkByName(name)
	if err != nil {
		return fmt.Errorf("find link %s: %w", name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

/* func ensureAddr(linkName, cidr string) error {
	link, err := linkByName(linkName)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, existing := range addrs {
		if existing.IPNet.String() == addr.IPNet.String() {
			return nil
		}
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add address %s to %s: %w",
			cidr, linkName, err)
	}
	return nil
} */

func ensureRoute(route *netlink.Route) error {
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("replace route %s table %d: %w",
			route.Dst, route.Table, err)
	}
	return nil
}

func ensureRule(family, priority, table int, iif string) error {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return err
	}

	for _, r := range rules {
		if r.Priority == priority &&
			r.Table == table &&
			r.IifName == iif {
			return nil
		}
	}

	r := netlink.NewRule()
	r.Family = family
	r.Priority = priority
	r.Table = table
	r.IifName = iif

	if err := netlink.RuleAdd(r); err != nil {
		return fmt.Errorf("add rule iif %s lookup %d: %w",
			iif, table, err)
	}
	return nil
}

func setSysctl(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("set sysctl %s=%s: %w", path, value, err)
	}
	return nil
}

func configureSysctls() error {
	// Enable IPv4 and IPv6 forwarding for the routed stages.
	settings := map[string]string{
		"/proc/sys/net/ipv4/ip_forward":          "1",
		"/proc/sys/net/ipv6/conf/all/forwarding": "1",
		"/proc/sys/net/ipv6/conf/all/seg6_enabled": "1",
	}

	for path, value := range settings {
		if err := setSysctl(path, value); err != nil {
			return err
		}
	}

	// Enable SRv6 processing on the interfaces that can receive outer IPv6
	// packets. This is especially relevant for the packet arriving on tun1.
	for _, name := range []string{Tun0, Tun1, VethIn, VethOut, Decap4} {
		path := "/proc/sys/net/ipv6/conf/" + name + "/seg6_enabled"
		if err := setSysctl(path, "1"); err != nil {
			return err
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------

func setupLinks() error {
	// Create TUN devices. Userspace opens these via /dev/net/tun.
	for _, name := range []string{Tun0, Tun1} {
		if err := ensureLink(&netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: name},
			Mode:      netlink.TUNTAP_MODE_TUN,
			Flags:     netlink.TUNTAP_NO_PI,
		}); err != nil {
			return err
		}
	}

	// Create the veth pair.
	if _, err := linkByName(VethIn); err != nil {
		if err := netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: VethIn},
			PeerName:  VethOut,
		}); err != nil {
			return fmt.Errorf("create veth pair: %w", err)
		}
	}

	// decap4 is a named dummy device. The SRv6 SID behavior is installed
	// separately as a seg6local route.
	if err := ensureLink(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: Decap4},
	}); err != nil {
		return err
	}

	for _, name := range []string{Tun0, Tun1, VethIn, VethOut, Decap4} {
		if err := ensureUp(name); err != nil {
			return err
		}
	}

	// Addresses allow veth-in to resolve veth-out as the default gateway.
	// if err := ensureAddr(VethIn, VethInAddr); err != nil {
	//	return err
	//}
	//if err := ensureAddr(VethOut, VethOutAddr); err != nil {
	//	return err
	//}

	return nil
}

func setupRoutesAndRules() error {
	tun0, err := linkByName(Tun0)
	if err != nil {
		return err
	}
	tun1, err := linkByName(Tun1)
	if err != nil {
		return err
	}
	vethIn, err := linkByName(VethIn)
	if err != nil {
		return err
	}
	// vethOut, err := linkByName(VethOut)
	// if err != nil {
	//	return err
	// }
	decap4, err := linkByName(Decap4)
	if err != nil {
		return err
	}

	targetNet := mustCIDR(TargetIPv4Net)
	decapSID := mustIP(DecapSID)
	legacySID := mustIP(LegacySID)

	// 1. Main IPv4 table:
	//    10.0.10.0/24 -> SRv6 encapsulation -> tun0.
	//
	// The internal segment slice is reversed: traversal order is
	// LegacySID (fd00::02), then DecapSID (fd00::03).
	encap := &netlink.SEG6Encap{
		Mode: nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: []net.IP{
			decapSID,
			legacySID,
		},
	}

	if err := ensureRoute(&netlink.Route{
		LinkIndex: tun0.Attrs().Index,
		Dst:       targetNet,
		Table:     MainTable,
		Family:    netlink.FAMILY_V4,
		Encap:     encap,
	}); err != nil {
		return err
	}

	// 2. Table 200:
	//    IPv4 packets reinjected through tun0 -> veth-in.
	//
	// Use the veth peer as gateway so Ethernet neighbor resolution works.
	if err := ensureRoute(&netlink.Route{
		LinkIndex: vethIn.Attrs().Index,
		Dst:       nil, // Default route: 0.0.0.0/0
		Table:     TableTun0,
		Family:    netlink.FAMILY_V4,
	}); err != nil {
		return err
	}

	// 3. Table 201:
	//    IPv4 packets arriving from veth-out -> tun1.
	if err := ensureRoute(&netlink.Route{
		LinkIndex: tun1.Attrs().Index,
		Table:     TableVeth,
		Family:    netlink.FAMILY_V4,
	}); err != nil {
		return err
	}

	// 4. Table 202:
	//    IPv6 packets reinjected through tun1, destined for the final SID,
	//    invoke END.DT4 and then route the inner IPv4 packet using table 254.
	//
	// The SID is a /128 route, not an ordinary interface address.
	var localFlags [nl.SEG6_LOCAL_MAX]bool
	localFlags[nl.SEG6_LOCAL_TABLE] = true

	endDT4 := &netlink.SEG6LocalEncap{
		Action: nl.SEG6_LOCAL_ACTION_END_DT4,
		Table:  MainTable,
		Flags:  localFlags,
	}

	sidRoute := &netlink.Route{
		LinkIndex: decap4.Attrs().Index,
		Dst:       netlink.NewIPNet(decapSID),
		Table:     TableTun1,
		Family:    netlink.FAMILY_V6,
		Encap:     endDT4,
	}

	if err := ensureRoute(sidRoute); err != nil {
		return err
	}

	// 5. Policy rules. Rule priorities and table IDs increase together.
	if err := ensureRule(
		netlink.FAMILY_V4, PriorityTun0, TableTun0, Tun0,
	); err != nil {
		return err
	}

	if err := ensureRule(
		netlink.FAMILY_V4, PriorityVeth, TableVeth, VethOut,
	); err != nil {
		return err
	}

	if err := ensureRule(
		netlink.FAMILY_V6, PriorityTun1, TableTun1, Tun1,
	); err != nil {
		return err
	}

	return nil
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Run as root (CAP_NET_ADMIN is required).")
		os.Exit(1)
	}

	if err := setupLinks(); err != nil {
		fmt.Fprintln(os.Stderr, "link setup:", err)
		os.Exit(1)
	}

	if err := configureSysctls(); err != nil {
		fmt.Fprintln(os.Stderr, "sysctl setup:", err)
		os.Exit(1)
	}

	if err := setupRoutesAndRules(); err != nil {
		fmt.Fprintln(os.Stderr, "route/rule setup:", err)
		os.Exit(1)
	}

	fmt.Println("SRv6 proxy development topology configured.")
}
