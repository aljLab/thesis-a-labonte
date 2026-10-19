//go:build linux
package setup

import (
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const (
	// Interface names.
	Tun0    = "tun0"
	Tun1    = "tun1"
	VethIn  = "veth-in"
	VethOut = "veth-out"
	Decap4  = "decap4" // VRF interface for End.DT4

	// IPv4 traffic to encapsulate.
	TargetIPv4Net = "10.0.10.0/24"

	// SRv6 SIDs.
	SIDPrefix = "fd00::/64"
	LegacySID = "fd00::02"
	DecapSID  = "fd00::03"

	// Routing tables for policy rules.
	TableTun0 = 200 // IPv4: iif tun0 -> veth-in
	TableVeth = 201 // IPv4: iif veth-out -> tun1
	TableTun1 = 202 // IPv6: iif tun1 -> End.DT4 SID

	// Priorities for policy rules.
	PriorityTun0 = 200
	PriorityVeth = 201
	PriorityTun1 = 202

	// The requested default IPv4 routing table.
	MainTable = unix.RT_TABLE_MAIN // 254
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

func getLink(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func ensureLink(link netlink.Link) error {
	name := link.Attrs().Name

	if existing, err := getLink(name); err == nil {
		fmt.Printf("link exists: %s (%s)\n", name, existing.Type())
		return nil
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create link %s: %w", name, err)
	}

	fmt.Printf("created link: %s\n", name)
	return nil
}

func ensureVethPair() error {
	_, errIn := getLink(VethIn)
	_, errOut := getLink(VethOut)

	if errIn == nil && errOut == nil {
		fmt.Println("veth pair already exists")
		return nil
	}

	if errIn == nil || errOut == nil {
		return fmt.Errorf(
			"inconsistent veth pair: %s and %s must either both exist or both be absent",
			VethIn, VethOut,
		)
	}

	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: VethIn},
		PeerName:  VethOut,
	}); err != nil {
		return fmt.Errorf("create veth pair: %w", err)
	}

	// get links by name
	linkIn, err := netlink.LinkByName(VethIn)
	if err != nil {
		return fmt.Errorf("get link %s: %w", VethIn, err)
	}

	linkOut, err := netlink.LinkByName(VethOut)
	if err != nil {
		return fmt.Errorf("get link %s: %w", VethOut, err)
	}

	// assign IP addresses in the same subnet
	for _, cfg := range []struct {
		link netlink.Link
		cidr string
	}{
		{link: linkIn, cidr: "10.30.0.2/30"},
		{link: linkOut, cidr: "10.30.0.1/30"},
	} {
		addr, err := netlink.ParseAddr(cfg.cidr)
		if err != nil {
			return fmt.Errorf("parse address %s: %w", cfg.cidr, err)
		}

		if err := netlink.AddrAdd(cfg.link, addr); err != nil {
			return fmt.Errorf("assign %s to %s: %w", cfg.cidr, cfg.link.Attrs().Name, err)
		}

		if err := netlink.LinkSetUp(cfg.link); err != nil {
			return fmt.Errorf("bring up %s: %w", cfg.link.Attrs().Name, err)
		}
	}

	fmt.Printf(
		"created veth pair: %s (10.30.0.2/30) <-> %s (10.30.0.1/30)\n",
		VethIn, VethOut,
	)
	return nil
}

func ensureVRF(name string, table uint32) error {
	if existing, err := getLink(name); err == nil {
		if existing.Type() != "vrf" {
			return fmt.Errorf(
				"interface %s exists but is type %q, not vrf; remove or rename it first",
				name, existing.Type(),
			)
		}
		return nil
	}

	if err := netlink.LinkAdd(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Table:     table,
	}); err != nil {
		return fmt.Errorf("create VRF %s, table %d: %w", name, table, err)
	}

	fmt.Printf("created VRF %s with table %d\n", name, table)
	return nil
}

func ensureUp(name string) error {
	link, err := getLink(name)
	if err != nil {
		return fmt.Errorf("find link %s: %w", name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}

	return nil
}

func ensureRoute(route *netlink.Route) error {
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf(
			"replace route dst=%v table=%d: %w",
			route.Dst, route.Table, err,
		)
	}

	return nil
}

func ensureRule(family, priority, table int, iif string) error {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return fmt.Errorf("list rules for family %d: %w", family, err)
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
		return fmt.Errorf(
			"add rule priority=%d iif=%s lookup=%d: %w",
			priority, iif, table, err,
		)
	}

	return nil
}

func writeSysctl(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("write %s=%s: %w", path, value, err)
	}
	return nil
}

func ConfigureSysctls(Tun0, Tun1 string) error {
	// The VRF must already exist before setting strict mode.
	if err := writeSysctl("/proc/sys/net/vrf/strict_mode", "1"); err != nil {
		return fmt.Errorf("enable VRF strict mode: %w", err)
	}

	if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		return err
	}

	if err := writeSysctl(
		"/proc/sys/net/ipv6/conf/all/forwarding", "1",
	); err != nil {
		return err
	}

	if err := writeSysctl(
		"/proc/sys/net/ipv6/conf/all/seg6_enabled", "1",
	); err != nil {
		return err
	}

	// disable rp_filter (v4)
	if err := writeSysctl(
		"/proc/sys/net/ipv4/conf/all/rp_filter", "0",
	); err != nil {
		return err
	}
	
	/*
	sysctl -w net.conf.ipv4.{all,tun0,tun1,veth-in,veth-out}.rp_filter=0
	sysctl -w net.conf.ipv4.{tun0,tun1,veth-in,veth-out},accept_local=1

	ip addr add 10.30.0.2/30 dev veth-in
	ip addr add 10.30.0.1/30 dev veth-out

	ip route replace default via 10.30.0.1/30 dev veth-in
	*/


	ifaces := []string{Tun0, Tun1, "veth-in", "veth-out"}

	for _, iface := range ifaces {
		if err := writeSysctl(
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface), "0",
		); err != nil {
			return err
		}

		if err := writeSysctl(
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/accept_local", iface), "1",
		); err != nil {
			return err
		}
	}

	for _, name := range []string{Tun0, Tun1, VethIn, VethOut, Decap4} {
		path := "/proc/sys/net/ipv6/conf/" + name + "/seg6_enabled"
		if err := writeSysctl(path, "1"); err != nil {
			return err
		}
	}

	return nil
}

func EnsureTunConfig(tun0, tun1 string) error {
	ifaces := []string{tun0, tun1}

	for _, iface := range ifaces {
		if err := writeSysctl(
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface), "0",
		); err != nil {
			return err
		}

		if err := writeSysctl(
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/accept_local", iface), "1",
		); err != nil {
			return err
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Interface creation
// -----------------------------------------------------------------------------

func SetupLinks(Tun0, Tun1 string) error {
	/* TUN devices: raw IP packets, no packet-information header.
	// for _, name := range []string{Tun0, Tun1} {
		if err := ensureLink(&netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: name},
			Mode:      netlink.TUNTAP_MODE_TUN,
			Flags:     netlink.TUNTAP_NO_PI,
		}); err != nil {
			return err
		}
	}*/

	// An unnumbered veth pair. No IP addresses are assigned.
	if err := ensureVethPair(); err != nil {
		return err
	}

	// decap4 is the VRF device used by the End.DT4 action.
	if err := ensureVRF(Decap4, uint32(MainTable)); err != nil {
		return err
	}

	for _, name := range []string{Tun0, Tun1, VethIn, VethOut, Decap4} {
		if err := ensureUp(name); err != nil {
			return err
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Routes and policy rules
// -----------------------------------------------------------------------------

func SetupRoutesAndRules(Tun0, Tun1 string) error {
	tun0, err := getLink(Tun0)
	if err != nil {
		return err
	}

	tun1, err := getLink(Tun1)
	if err != nil {
		return err
	}

	vethIn, err := getLink(VethIn)
	if err != nil {
		return err
	}

	_, err = getLink(VethOut)
	if err != nil {
		return err
	}

	decap4, err := getLink(Decap4)
	if err != nil {
		return err
	}

	// 1. Main IPv4 table:
	//
	//    10.0.10.0/24
	//        -> SRv6 encapsulation
	//        -> tun0
	//
	// Traversal order:
	//    fd00::02 (legacy function), then fd00::03 (End.DT4).
	//
	// netlink represents the SRH segment list in reverse order.
	encap := &netlink.SEG6Encap{
		Mode: nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: []net.IP{
			mustIP(DecapSID),
			mustIP(LegacySID),
		},
	}

	if err := ensureRoute(&netlink.Route{
		LinkIndex: tun0.Attrs().Index,
		Dst:       mustCIDR(TargetIPv4Net),
		Table:     MainTable,
		Family:    netlink.FAMILY_V4,
		Encap:     encap,
	}); err != nil {
		return err
	}

	// 2. Table 200:
	//
	//    IPv4 packets reinjected through tun0
	//        -> default route
	//        -> veth-in
	//
	// Device route: gw is veth peer with 10.30.0.1
	if err := ensureRoute(&netlink.Route{
		LinkIndex: vethIn.Attrs().Index,
		Gw:        net.IPv4(10, 30, 0, 1),
		Dst:       mustCIDR("0.0.0.0/30"),
		Table:     TableTun0,
		Family:    netlink.FAMILY_V4,
	}); err != nil {
		return err
	}

	// 3. Table 201:
	//
	//    IPv4 packets received on veth-out
	//        -> default route
	//        -> tun1
	if err := ensureRoute(&netlink.Route{
		LinkIndex: tun1.Attrs().Index,
		Dst:       mustCIDR("0.0.0.0/0"),
		Table:     TableVeth,
		Family:    netlink.FAMILY_V4,
	}); err != nil {
		return err
	}

	// 4. Table 202:
	//
	//    IPv6 packets reinjected through tun1 and destined to fd00::03
	//        -> End.DT4
	//        -> decap4 VRF, table 254
	//
	// End.DT4 requires VRF-table mode. Setting SEG6_LOCAL_TABLE here
	// would be incorrect: use SEG6_LOCAL_VRFTABLE and VrfTable.
	var flags [nl.SEG6_LOCAL_MAX]bool
	flags[nl.SEG6_LOCAL_ACTION] = true
	flags[nl.SEG6_LOCAL_VRFTABLE] = true

	endDT4 := &netlink.SEG6LocalEncap{
		Action:   nl.SEG6_LOCAL_ACTION_END_DT4,
		VrfTable: MainTable,
		Flags:    flags,
	}

	if err := ensureRoute(&netlink.Route{
		LinkIndex: decap4.Attrs().Index,
		Dst:       mustCIDR(DecapSID + "/128"),
		Table:     TableTun1,
		Family:    netlink.FAMILY_V6,
		Encap:     endDT4,
	}); err != nil {
		return err
	}

	// 5. Policy-routing rules.
	//
	// IPv4:
	//    iif tun0    -> table 200 -> veth-in
	//    iif veth-out -> table 201 -> tun1
	//
	// IPv6:
	//    iif tun1    -> table 202 -> End.DT4 SID route
	//
	// The rules are ingress-interface-specific.
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

	// 6. Route to SID network via tun0:
	//
	//    IPv6 packets received with dst fd00::/64
	//        -> default route
	//        -> tun1
	if err := ensureRoute(&netlink.Route{
		LinkIndex: tun0.Attrs().Index,
		Dst:       mustCIDR("fd00::/64"),
		Family:    netlink.FAMILY_V6,
	}); err != nil {
		return err
	}

	// 7. Route to 10.0.20.0/24 network via tun1 -> encap testing:
	//
	//    IPv4 packets received with dst 10.0.20.0/24
	//        -> tun1
	if err := ensureRoute(&netlink.Route{
		LinkIndex: tun1.Attrs().Index,
		Dst:       mustCIDR("10.0.20.0/24"),
		Family:    netlink.FAMILY_V4,
	}); err != nil {
		return err
	}

	return nil
}

func main() {
	/* if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Run as root; CAP_NET_ADMIN is required.")
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
 */
	fmt.Println("SRv6 proxy topology configured.")
}
