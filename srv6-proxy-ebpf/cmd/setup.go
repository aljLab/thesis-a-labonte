// go:build linux
package main

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

const (
	BOGUS_IPV6 = "fd00:0:0:37::1"
)

type Config struct {
	InIfaces          []string
	OutIfaces         []string
	DispatchVeth      string
	BridgePortVeth    string
	RoutingBridgeName string
}

type MacIndexMapping struct {
	Mac       net.HardwareAddr
	LinkIndex uint32
}

/*
PACKET WALK: p1 arrives encapsulated at routing bridge (router-vrf)
-> IN RoutingBridge -> finds route: dst <SID-of-LEGACY-NF> dev <BridgePortVeth> via <BOGUS-IP> (permanent neighbor for DispatchVeth MAC to BogusIP)
-> IN DispatchVeth -> XDP decap program
-> decaps/caches, picks lane, looks up index of out dev and mac addr of peer-of-out-dev
-> OUT InIfaceN
-> IN OutIfaceN -> XDP encap program -> reencapsulate -> lookup mac of routing bridge -> update eth -> redirect_to(bridgeport)
*/

func setup(conf *Config) (map[string]MacIndexMapping, error) {
	if len(conf.InIfaces) != len(conf.OutIfaces) {
		return nil, fmt.Errorf("InIfaces (%d) and OutIfaces (%d) must have the same length",
			len(conf.InIfaces), len(conf.OutIfaces))
	}

	// Track everything we create so a failure part-way leaves nothing behind.
	var created []netlink.Link
	ok := false
	defer func() {
		if ok {
			return
		}
		for _, l := range created {
			_ = netlink.LinkDel(l) // deleting one end of a veth removes its peer too
		}
	}()

	// create routing bridge with RoutingBridgeName
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: conf.RoutingBridgeName}}
	if err := netlink.LinkAdd(br); err != nil {
		return nil, fmt.Errorf("create bridge %s: %w", conf.RoutingBridgeName, err)
	}
	created = append(created, br)

	addVeth := func(name, peer string) error {
		v := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: name},
			PeerName:  peer,
		}
		if err := netlink.LinkAdd(v); err != nil {
			return fmt.Errorf("create veth %s<->%s: %w", name, peer, err)
		}
		created = append(created, v)
		return nil
	}

	// create veth pairs for (InIfaces[i], OutIfaces[i]) for i in [0, len-1]
	for i := range conf.InIfaces {
		if err := addVeth(conf.InIfaces[i], conf.OutIfaces[i]); err != nil {
			return nil, err
		}
	}

	// create veth pair (DispatchVeth, BridgePortVeth) and enslave BridgePortVeth to the RoutingBridge
	if err := addVeth(conf.DispatchVeth, conf.BridgePortVeth); err != nil {
		return nil, err
	}
	bridgePort, err := netlink.LinkByName(conf.BridgePortVeth)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", conf.BridgePortVeth, err)
	}
	bridge, err := netlink.LinkByName(conf.RoutingBridgeName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", conf.RoutingBridgeName, err)
	}
	if err := netlink.LinkSetMaster(bridgePort, bridge); err != nil {
		return nil, fmt.Errorf("enslave %s to %s: %w", conf.BridgePortVeth, conf.RoutingBridgeName, err)
	}

	// set all interfaces up
	// (done before reading MACs: the bridge's MAC can change once a port joins)
	allNames := make([]string, 0, len(conf.InIfaces)+len(conf.OutIfaces)+3)
	allNames = append(allNames, conf.InIfaces...)
	allNames = append(allNames, conf.OutIfaces...)
	allNames = append(allNames, conf.DispatchVeth, conf.BridgePortVeth, conf.RoutingBridgeName)
	for _, name := range allNames {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("lookup %s: %w", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return nil, fmt.Errorf("set %s up: %w", name, err)
		}
	}

	// get the mac addresses and indices and populate return map with each endpoint: ifaceName -> {Mac, LinkIndex}
	macIndexMap := make(map[string]MacIndexMapping, len(conf.InIfaces)+len(conf.OutIfaces)+2)
	// map order: inIfaces..., outifaces..., dispatchVeth, RoutingBridge
	var dispatchMac net.HardwareAddr
	lookup := func(name string) error {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return fmt.Errorf("lookup %s: %w", name, err)
		}
		attrs := l.Attrs()
		mac := make(net.HardwareAddr, len(attrs.HardwareAddr))
		copy(mac, attrs.HardwareAddr)
		macIndexMap[name] = MacIndexMapping{Mac: mac, LinkIndex: uint32(attrs.Index)}
		if name == conf.DispatchVeth {
			dispatchMac = mac
		}
		return nil
	}
	ordered := make([]string, 0, len(conf.InIfaces)+len(conf.OutIfaces)+2)
	ordered = append(ordered, conf.InIfaces...)
	ordered = append(ordered, conf.OutIfaces...)
	ordered = append(ordered, conf.DispatchVeth, conf.RoutingBridgeName)
	for _, name := range ordered {
		if err := lookup(name); err != nil {
			return nil, err
		}
	}

	// create ip neighbor entry for Bogus-IP with lladdr <mac-of-DispatchVeth> nud permanent
	// (equivalent: ip -6 neigh replace fd00:0:0:37::1 lladdr <mac> dev <BridgePortVeth> nud permanent)
	// It lives on BridgePortVeth, the egress device of the route, so the bridge resolves
	// the next hop to the DispatchVeth end of the pair.
	bogus := net.ParseIP(BOGUS_IPV6)
	if bogus == nil {
		return nil, fmt.Errorf("invalid BOGUS_IPV6 %q", BOGUS_IPV6)
	}
	neigh := &netlink.Neigh{
		LinkIndex:    bridgePort.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           bogus,
		HardwareAddr: dispatchMac,
	}
	if err := netlink.NeighSet(neigh); err != nil {
		return nil, fmt.Errorf("add permanent neighbor %s lladdr %s dev %s: %w",
			BOGUS_IPV6, dispatchMac, conf.BridgePortVeth, err)
	}

	ok = true
	return macIndexMap, nil
}