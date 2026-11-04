// Package setup builds and removes the ingress/egress routing topology.
//
// Requires root (CAP_NET_ADMIN) and the following modules:
//
//	go get github.com/vishvananda/netlink golang.org/x/sys/unix
//
// The tun devices "tun0" and "tun1" must already exist; they are never
// created or removed by this package.
package setup

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tunIngress = "tun0"
	tunEgress  = "tun1"

	bridgeName = "routing-bridge"
	vrfName    = "ingress-vrf"

	// Routing table that backs ingress-vrf.
	vrfTable = 100

	// Ingress
	bridgeIn    = "bridge-in"
	ingressVeth = "ingress-veth"
	vethIn      = "veth-in"
	vethOut     = "veth-out"

	vethInCIDR  = "10.30.0.2/30"
	vethOutCIDR = "10.30.0.1/30"
	vethOutIP   = "10.30.0.1"

	// IPv6 equivalents (ULA, /126 like the IPv4 /30)
	vethInCIDR6  = "fd00:30::2/126"
	vethOutCIDR6 = "fd00:30::1/126"
	vethOutIP6   = "fd00:30::1"

	// The kernel refuses an IPv6 route whose (global) gateway is a local
	// address ("Gateway can not be a local address" -> EINVAL). Since
	// veth-out lives on this very host, the v6 next hop has to be a
	// link-local address instead; it is assigned statically to veth-out.
	vethOutGwCIDR6 = "fe80::1/64"
	vethOutGw6     = "fe80::1"

	tableIngress = 200 // iif tun0 -> default via veth-out's address

	// Egress
	egressVeth = "egress-veth"
	bridgeOut  = "bridge-out"

	egressVethCIDR = "10.40.0.2/30"
	bridgeOutCIDR  = "10.40.0.1/30"
	bridgeOutIP    = "10.40.0.1"

	// IPv6 equivalents
	egressVethCIDR6 = "fd00:40::2/126"
	bridgeOutCIDR6  = "fd00:40::1/126"
	bridgeOutIP6    = "fd00:40::1"

	// Link-local next hop on bridge-out (see the note on vethOutGw6).
	bridgeOutGwCIDR6 = "fe80::1/64"
	bridgeOutGw6     = "fe80::1"

	tableEgress = 201 // iif veth-out -> default dev tun1
	tableReturn = 202 // iif tun1     -> default via bridge-out

	// Rule priorities (explicit, so that add/delete are deterministic).
	prioIngress = 1000
	prioEgress  = 1001
	prioReturn  = 1002
)

var (
	defaultV4 = &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}
	defaultV6 = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
)

// Setup creates the topology. It is idempotent: running it repeatedly (or on
// a partially built topology) converges to the same end state.
func Setup() error {
	tun0, err := requireLink(tunIngress)
	if err != nil {
		return err
	}
	tun1, err := requireLink(tunEgress)
	if err != nil {
		return err
	}

	// --- Global sysctls (set first so new links inherit the defaults) -------
	for path, val := range map[string]string{
		"net/ipv4/ip_forward":                           "1",
		"net/ipv6/conf/all/forwarding":                  "1",
		"net/ipv6/conf/default/forwarding":              "1",
		"net/ipv6/conf/all/seg6_enabled":                "1",
		"net/ipv6/conf/default/seg6_enabled":            "1",
		"net/ipv6/conf/" + tunIngress + "/seg6_enabled": "1",
		"net/ipv6/conf/" + tunEgress + "/seg6_enabled":  "1",
	} {
		if err := sysctlSet(path, val); err != nil {
			return err
		}
	}

	// --- Ingress -------------------------------------------------------------
	br, err := ensureBridge(bridgeName)
	if err != nil {
		return err
	}
	vrf, err := ensureVrf(vrfName, vrfTable)
	if err != nil {
		return err
	}

	bIn, ingVeth, err := ensureVethPair(bridgeIn, ingressVeth)
	if err != nil {
		return err
	}
	if err := setMaster(bIn, br); err != nil {
		return err
	}
	if err := setMaster(ingVeth, vrf); err != nil {
		return err
	}
	if err := setUp(bIn, ingVeth); err != nil {
		return err
	}

	// default (IPv6) route in ingress-vrf via tun0
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: tun0.Attrs().Index,
		Dst:       defaultV6,
		Table:     vrfTable,
	}); err != nil {
		return fmt.Errorf("vrf default route: %w", err)
	}

	vIn, vOut, err := ensureVethPair(vethIn, vethOut)
	if err != nil {
		return err
	}
	for _, cidr := range []string{vethInCIDR, vethInCIDR6} {
		if err := addAddr(vIn, cidr); err != nil {
			return err
		}
	}
	for _, cidr := range []string{vethOutCIDR, vethOutCIDR6, vethOutGwCIDR6} {
		if err := addAddr(vOut, cidr); err != nil {
			return err
		}
	}
	if err := setUp(vIn, vOut); err != nil {
		return err
	}
	// Refresh to make sure we read the final MAC.
	if vOut, err = netlink.LinkByName(vethOut); err != nil {
		return err
	}

	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		if err := ensureRule(newRule(tunIngress, tableIngress, prioIngress, fam)); err != nil {
			return err
		}
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: vIn.Attrs().Index,
		Dst:       defaultV4,
		Gw:        net.ParseIP(vethOutIP),
		Table:     tableIngress,
	}); err != nil {
		return fmt.Errorf("table %d default route: %w", tableIngress, err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: vIn.Attrs().Index,
		Dst:       defaultV6,
		Gw:        net.ParseIP(vethOutGw6),
		Table:     tableIngress,
	}); err != nil {
		return fmt.Errorf("table %d v6 default route: %w", tableIngress, err)
	}
	for _, ip := range []string{vethOutIP, vethOutIP6, vethOutGw6} {
		if err := setNeigh(vIn, ip, vOut.Attrs().HardwareAddr); err != nil {
			return err
		}
	}

	// --- Egress --------------------------------------------------------------
	eVeth, bOut, err := ensureVethPair(egressVeth, bridgeOut)
	if err != nil {
		return err
	}
	if err := setMaster(bOut, br); err != nil {
		return err
	}
	for _, cidr := range []string{egressVethCIDR, egressVethCIDR6} {
		if err := addAddr(eVeth, cidr); err != nil {
			return err
		}
	}
	for _, cidr := range []string{bridgeOutCIDR, bridgeOutCIDR6, bridgeOutGwCIDR6} {
		if err := addAddr(bOut, cidr); err != nil {
			return err
		}
	}
	if err := setUp(br, vrf, eVeth, bOut); err != nil {
		return err
	}
	if bOut, err = netlink.LinkByName(bridgeOut); err != nil {
		return err
	}

	// iif veth-out -> table 201 (v4 + v6), default via tun1
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		if err := ensureRule(newRule(vethOut, tableEgress, prioEgress, fam)); err != nil {
			return err
		}
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: tun1.Attrs().Index,
		Dst:       defaultV4,
		Scope:     netlink.SCOPE_LINK,
		Table:     tableEgress,
	}); err != nil {
		return fmt.Errorf("table %d v4 default route: %w", tableEgress, err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: tun1.Attrs().Index,
		Dst:       defaultV6,
		Table:     tableEgress,
	}); err != nil {
		return fmt.Errorf("table %d v6 default route: %w", tableEgress, err)
	}

	// iif tun1 -> table 202, default via 10.40.0.1 dev egress-veth
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		if err := ensureRule(newRule(tunEgress, tableReturn, prioReturn, fam)); err != nil {
			return err
		}
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: eVeth.Attrs().Index,
		Dst:       defaultV4,
		Gw:        net.ParseIP(bridgeOutIP),
		Table:     tableReturn,
	}); err != nil {
		return fmt.Errorf("table %d default route: %w", tableReturn, err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: eVeth.Attrs().Index,
		Dst:       defaultV6,
		Gw:        net.ParseIP(bridgeOutGw6),
		Table:     tableReturn,
	}); err != nil {
		return fmt.Errorf("table %d v6 default route: %w", tableReturn, err)
	}
	for _, ip := range []string{bridgeOutIP, bridgeOutIP6, bridgeOutGw6} {
		if err := setNeigh(eVeth, ip, bOut.Attrs().HardwareAddr); err != nil {
			return err
		}
	}

	// --- Per-interface rp_filter (asymmetric paths would otherwise be dropped).
	// Note: the kernel uses max(all, <iface>), so a global "all" value > 0 still wins.
	for _, name := range []string{vethIn, vethOut, egressVeth, bridgeOut, tunIngress, tunEgress} {
		if err := sysctlSet("net/ipv4/conf/"+name+"/rp_filter", "0"); err != nil {
			return err
		}
	}

	return nil
}

// TearDown removes everything Setup created (rules, routes, devices).
// Global sysctls (forwarding, seg6) are left untouched, and the tun devices
// are never removed. It is safe to call repeatedly.
func TearDown() error {
	var errs []error

	rules := []*netlink.Rule{
		newRule(tunIngress, tableIngress, prioIngress, unix.AF_INET),
		newRule(tunIngress, tableIngress, prioIngress, unix.AF_INET6),
		newRule(vethOut, tableEgress, prioEgress, unix.AF_INET),
		newRule(vethOut, tableEgress, prioEgress, unix.AF_INET6),
		newRule(tunEgress, tableReturn, prioReturn, unix.AF_INET),
		newRule(tunEgress, tableReturn, prioReturn, unix.AF_INET6),
	}
	for _, r := range rules {
		if err := netlink.RuleDel(r); err != nil && !isNotExist(err) {
			errs = append(errs, fmt.Errorf("delete rule iif %s: %w", r.IifName, err))
		}
	}

	// Flush routes in our tables (table 201 contains routes via tun1, which
	// would otherwise outlive our devices).
	for _, table := range []int{tableIngress, tableEgress, tableReturn, vrfTable} {
		for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				errs = append(errs, fmt.Errorf("list routes table %d: %w", table, err))
				continue
			}
			for i := range routes {
				if err := netlink.RouteDel(&routes[i]); err != nil && !isNotExist(err) {
					errs = append(errs, fmt.Errorf("delete route in table %d: %w", table, err))
				}
			}
		}
	}

	// Deleting one end of a veth pair removes the peer as well; deleting both
	// names explicitly is harmless and handles half-built pairs.
	for _, name := range []string{
		vethIn, vethOut,
		egressVeth, bridgeOut,
		bridgeIn, ingressVeth,
		vrfName, bridgeName,
	} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			if isLinkNotFound(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("lookup %s: %w", name, err))
			continue
		}
		if err := netlink.LinkDel(link); err != nil && !isNotExist(err) {
			errs = append(errs, fmt.Errorf("delete link %s: %w", name, err))
		}
	}

	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func requireLink(name string) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("required device %q: %w", name, err)
	}
	return l, nil
}

func ensureBridge(name string) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	if err == nil {
		if l.Type() != "bridge" {
			return nil, fmt.Errorf("%s exists but is a %s, not a bridge", name, l.Type())
		}
		return l, nil
	}
	if !isLinkNotFound(err) {
		return nil, err
	}
	if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		return nil, fmt.Errorf("create bridge %s: %w", name, err)
	}
	return netlink.LinkByName(name)
}

func ensureVrf(name string, table uint32) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	if err == nil {
		v, ok := l.(*netlink.Vrf)
		if !ok {
			return nil, fmt.Errorf("%s exists but is a %s, not a vrf", name, l.Type())
		}
		if v.Table != table {
			return nil, fmt.Errorf("vrf %s exists with table %d, want %d", name, v.Table, table)
		}
		return l, nil
	}
	if !isLinkNotFound(err) {
		return nil, err
	}
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name}, Table: table}); err != nil {
		return nil, fmt.Errorf("create vrf %s: %w", name, err)
	}
	return netlink.LinkByName(name)
}

// ensureVethPair returns both ends of the pair, creating it if needed. If only
// one end exists (broken state), the leftover is removed and the pair recreated.
func ensureVethPair(name, peer string) (netlink.Link, netlink.Link, error) {
	a, errA := netlink.LinkByName(name)
	b, errB := netlink.LinkByName(peer)
	for _, e := range []error{errA, errB} {
		if e != nil && !isLinkNotFound(e) {
			return nil, nil, e
		}
	}

	if errA == nil && errB == nil && a.Type() == "veth" && b.Type() == "veth" {
		return a, b, nil
	}

	// Clean up leftovers, then recreate.
	for _, l := range []netlink.Link{a, b} {
		if l != nil {
			if err := netlink.LinkDel(l); err != nil && !isNotExist(err) {
				return nil, nil, fmt.Errorf("remove stale %s: %w", l.Attrs().Name, err)
			}
		}
	}
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  peer,
	}); err != nil {
		return nil, nil, fmt.Errorf("create veth %s<->%s: %w", name, peer, err)
	}
	a, err := netlink.LinkByName(name)
	if err != nil {
		return nil, nil, err
	}
	b, err = netlink.LinkByName(peer)
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

func setMaster(link, master netlink.Link) error {
	if link.Attrs().MasterIndex == master.Attrs().Index {
		return nil
	}
	if err := netlink.LinkSetMaster(link, master); err != nil {
		return fmt.Errorf("enslave %s to %s: %w", link.Attrs().Name, master.Attrs().Name, err)
	}
	return nil
}

func setUp(links ...netlink.Link) error {
	for _, l := range links {
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("set %s up: %w", l.Attrs().Name, err)
		}
	}
	return nil
}

func addAddr(link netlink.Link, cidr string) error {
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if addr.IP.To4() == nil {
		// Skip DAD so the address is usable immediately (needed for the
		// gateway routes and static neighbors below).
		addr.Flags |= unix.IFA_F_NODAD
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("address %s on %s: %w", cidr, link.Attrs().Name, err)
	}
	return nil
}

func setNeigh(link netlink.Link, ip string, mac net.HardwareAddr) error {
	if len(mac) == 0 {
		return fmt.Errorf("no MAC address known for neighbor %s on %s", ip, link.Attrs().Name)
	}
	parsed := net.ParseIP(ip)
	family := netlink.FAMILY_V6
	if parsed.To4() != nil {
		family = netlink.FAMILY_V4
	}
	err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       family,
		State:        netlink.NUD_PERMANENT,
		IP:           parsed,
		HardwareAddr: mac,
	})
	if err != nil {
		return fmt.Errorf("neighbor %s on %s: %w", ip, link.Attrs().Name, err)
	}
	return nil
}

func newRule(iif string, table, prio, family int) *netlink.Rule {
	r := netlink.NewRule()
	r.IifName = iif
	r.Table = table
	r.Priority = prio
	r.Family = family
	return r
}

func ensureRule(r *netlink.Rule) error {
	if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add rule iif %s lookup %d: %w", r.IifName, r.Table, err)
	}
	return nil
}

func sysctlSet(path, val string) error {
	if err := os.WriteFile("/proc/sys/"+path, []byte(val), 0o644); err != nil {
		return fmt.Errorf("sysctl %s=%s: %w", path, val, err)
	}
	return nil
}

func isLinkNotFound(err error) bool {
	var lnf netlink.LinkNotFoundError
	return errors.As(err, &lnf)
}

func isNotExist(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ESRCH) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.EADDRNOTAVAIL) ||
		isLinkNotFound(err)
}