//go:build linux
package main

import (
	"fmt"
	"net"
	"slices"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	// SEND/RECEIVE mean send/receive to/from the non-srv6 capable nf
	// creating tun interface for SEND/DECAP
	decapTun, err := tun.CreateTUN("decapTun", 1294)
	if err != nil {
		fmt.Println(err)
		return
	}

	decap_name, err := decapTun.Name()
	if err != nil {
		fmt.Println("Couldnt get name of decap Tun device")
	}

	tun0iface, err := netlink.LinkByName(decap_name)
	if err != nil {
		fmt.Println("Couldnt get decap interface by name")
	}

	if err := netlink.LinkSetUp(tun0iface); err != nil {
		fmt.Println("Couldnt set decap link up.")
		return
	}

	// creating tun interface for RECEIVE/ENCAP
	encapTun, err := tun.CreateTUN("encapTun", 1294)
	if err != nil {
		fmt.Println(err)
		return
	}

	encap_name, err := encapTun.Name()
	if err != nil {
		fmt.Println("Couldnt get name of encap Tun device")
	}

	tun1iface, err := netlink.LinkByName(encap_name)
	if err != nil {
		fmt.Println("Couldnt get encap interface by name")
	}

	if err := netlink.LinkSetUp(tun1iface); err != nil {
		fmt.Println("Couldnt set encap link up.")
		return
	}

	// creating routes
	// fd00::/64 --> decapTun
	// decapTun --> enp94s0f0np0
	// enp5es0f0s5 --> encapTun
	// encapTun --> br0
	dstNet := &net.IPNet{
		IP:   net.IP{0xfd, 0x00, 00, 00, 00, 00, 00, 0x01, 00, 00, 00, 00, 00, 00, 00, 00},
		Mask: net.CIDRMask(64, 128),
	}

	_, v4TargetNet, _ := net.ParseCIDR("10.0.10.0/24")

	err = addTestingRoutes(*v4TargetNet, tun0iface); if err != nil {
		fmt.Println("Couldn't add testing routes %s", err)
	}

	err  = ensureRoutes(tun0iface, dstNet, decap_name, encap_name); if err != nil {
		fmt.Println("Couldn't configure routes %s", err)
	}

	echoTunnel(decapTun)
	
}

func addTestingRoutes(dstNet net.IPNet, tun netlink.Link) error {
	bridge, err := netlink.LinkByName("br0"); if err != nil {
		return fmt.Errorf("failed to get bridge br0: %w", err)
	}

	err = netlink.LinkSetUp(bridge); if err != nil {
		return fmt.Errorf("failed to set bridge br0 up: %w", err)
	}
	
	decapIface := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "decap0",
		},
		PeerName: "decap0pipe",
	}

	if err := netlink.LinkAdd(decapIface); err != nil {
		return fmt.Errorf("failed to add decap interface: %w", err)
	}

	if err := netlink.LinkSetMaster(decapIface, bridge); err != nil {
		return fmt.Errorf("failed to set master for decap interface: %w", err)
	}
	if err := netlink.LinkSetUp(decapIface); err != nil {
		return fmt.Errorf("failed to set up decap interface: %w", err)
	}
	decapPeer, err := netlink.LinkByName("decap0pipe")
	if err != nil {
		return fmt.Errorf("failed to get decap peer interface: %w", err)
	}
	if err = netlink.LinkSetMaster(decapPeer, bridge); err != nil {
		return fmt.Errorf("failed to set master for decap peer interface: %w", err)
	}
	if err = netlink.LinkSetUp(decapPeer); err != nil {
		return fmt.Errorf("failed to set up decap peer interface: %w", err)
	}
	// create decap interface 
	decapSidv4, _, _ := net.ParseCIDR("fd::04/64");
	// ip -6 route add <decap sid> table <router vrf table> encap seg6local action End.DT4 table <router vrf table> dev <decap iface>
	var flagsEndDt4Encaps [nl.SEG6_LOCAL_MAX]bool
	flagsEndDt4Encaps[nl.SEG6_LOCAL_ACTION] = true
	flagsEndDt4Encaps[nl.SEG6_LOCAL_VRFTABLE] = true
	decapRoutev4 := &netlink.Route{
		Dst: &net.IPNet{
			IP:   decapSidv4,
			Mask: net.CIDRMask(128, 128),
		},
		// Table: 100,
		Encap: &netlink.SEG6LocalEncap{
			Flags:    flagsEndDt4Encaps,
			Action:   nl.SEG6_LOCAL_ACTION_END_DT4,
			//VrfTable: 100,
		},
		LinkIndex: decapIface.Attrs().Index,
	}
	if err = netlink.RouteAdd(decapRoutev4); err != nil {
		err = fmt.Errorf(
			"failed to execute `ip -6 route add %s table %d encap seg6local action End.DT4 vrftable %d dev %s`: %s",
			decapSidv4.String(), 100, 100, decapIface.Attrs().Name, err)
		return fmt.Errorf("failed to add decap route: %w", err)
	}

	// add routes to encapsulate/decapsulate SRv6 packets
	sid1, _, _ := net.ParseCIDR("fd00::02/64")
	sid2, _, _ := net.ParseCIDR("fd00::03/64")
	sids := []net.IP{
		sid1,
		sid2,
	}
	ipv4sids := append(sids, decapSidv4)
	slices.Reverse(ipv4sids)
	
	route := &netlink.Route{
		Dst:   &dstNet,
		// Table: int(s.Vrf.Table),
		Encap: &netlink.SEG6Encap{
			Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
			Segments: ipv4sids,
		},
		LinkIndex: tun.Attrs().Index,
	}

	err = netlink.RouteAdd(route); if err != nil {
		return fmt.Errorf("failed to add encap route: %w", err)
	}

	return nil
}

func ensureRoutes(tun0iface netlink.Link, dstNet *net.IPNet, decap_name, encap_name string) error {
	
	// dst --> decapTun
	route0 := netlink.Route{
		LinkIndex: tun0iface.Attrs().Index,
		Dst:       dstNet,
		Family:    10,
	}

	if err := netlink.RouteReplace(&route0); err != nil {
		return fmt.Errorf("Failed replacing route")
	}

	// decapTun --> enp94s0f0np0
	const table200 = 200
	const priority = 100

	// Rule: packets arriving on tun0 consult table 200.
	rule := netlink.NewRule()
	rule.Family = 10
	rule.Priority = priority
	rule.IifName = decap_name
	rule.Table = table200

	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add policy rule: %w", err)
	}

	// Resolve the output interface.
	inIface, err := netlink.LinkByName("enp94s0f0np0")
	if err != nil {
		fmt.Errorf("find enp94s0f0np0: %w", err)
	}

	route := netlink.Route{
		LinkIndex: inIface.Attrs().Index,
		// Gw:        gw, not needed, directly connected BlueField
		Table:  table200,
		Family: 10,
		Scope:  netlink.SCOPE_UNIVERSE,
	}

	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("replace route in table %d: %w", table200, err)
	}

	// enp5es0f0s5 --> encapTun
	const table300 = 300

	// Rule: packets arriving on tun0 consult table 300.
	rule1 := netlink.NewRule()
	rule1.Family = 10
	rule1.Priority = priority
	rule1.IifName = "enp5es0f0s5"
	rule1.Table = table300

	if err := netlink.RuleAdd(rule1); err != nil {
		return fmt.Errorf("add policy rule: %w", err)
	}

	// Resolve the output interface.
	outIface, err := netlink.LinkByName(encap_name)
	if err != nil {
		return fmt.Errorf("find %s: %w", encap_name, err)
	}

	route1 := netlink.Route{
		LinkIndex: outIface.Attrs().Index,
		// Gw:        gw, not needed, directly connected BlueField
		Table:  table300,
		Family: 10,
		Scope:  netlink.SCOPE_UNIVERSE,
	}

	if err := netlink.RouteReplace(&route1); err != nil {
		return fmt.Errorf("replace route in table %d: %w", table300, err)
	}
	// encapTun --> br0
	const table400 = 400

	// Rule: packets arriving on tun0 consult table 300.
	rule2 := netlink.NewRule()
	rule2.Family = 10
	rule2.Priority = priority
	rule2.IifName = "encapTun"
	rule2.Table = table400

	if err := netlink.RuleAdd(rule2); err != nil {
		return fmt.Errorf("add policy rule: %w", err)
	}

	// Resolve the output interface.
	bridgeIface, err := netlink.LinkByName("br0")
	if err != nil {
		return fmt.Errorf("find %s: %w", encap_name, err)
	}

	route2 := netlink.Route{
		LinkIndex: bridgeIface.Attrs().Index,
		// Gw:        gw, not needed, directly connected BlueField
		Table:  table400,
		Family: 10,
		Scope:  netlink.SCOPE_UNIVERSE,
	}

	if err := netlink.RouteReplace(&route2); err != nil {
		return fmt.Errorf("replace route in table %d: %w", table400, err)
	}

	return nil
}

func echoTunnel(dev tun.Device) error {
	buf := make([]byte, 65535)
	bufs := [][]byte{buf}
	sizes := make([]int, 1)

	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			return fmt.Errorf("read from TUN: %w", err)
		}

		for i := 0; i < n; i++ {
			packet := bufs[i][:sizes[i]]

			if _, err := dev.Write([][]byte{packet}, 0); err != nil {
				return fmt.Errorf("write to TUN: %w", err)
			}
		}
	}
}
