package setup

import (
	"errors"
	"log"
	"net"
	"syscall"

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

// logErr logs a non-fatal failure; setup never aborts on errors.
func logErr(what string, err error) {
	if err != nil {
		log.Printf("setup: %s: %v", what, err)
	}
}

// ensureLink adds the link unless it already exists. EEXIST is not an error.
func ensureLink(l netlink.Link) {
	name := l.Attrs().Name
	if _, err := netlink.LinkByName(name); err == nil {
		return // already there
	}
	if err := netlink.LinkAdd(l); err != nil && !errors.Is(err, syscall.EEXIST) {
		logErr("create link "+name, err)
	}
}

// ensureVeth creates the pair unless either end already exists.
func ensureVeth(name, peer string) {
	if _, err := netlink.LinkByName(name); err == nil {
		return
	}
	if _, err := netlink.LinkByName(peer); err == nil {
		return
	}
	ensureLink(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  peer,
	})
}

// Idempotent: safe to call repeatedly, existing objects are reused, and failures
// are logged rather than returned. The returned error is always nil; the
// signature is kept so callers don't change.
func Setup(conf *Config) ([]MacIndexMapping, error) {
	if len(conf.InIfaces) != len(conf.OutIfaces) {
		log.Printf("setup: InIfaces (%d) and OutIfaces (%d) differ in length; pairing only the first %d",
			len(conf.InIfaces), len(conf.OutIfaces), min(len(conf.InIfaces), len(conf.OutIfaces)))
	}

	// create routing bridge with RoutingBridgeName
	ensureLink(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: conf.RoutingBridgeName}})

	// create veth pairs for (InIfaces[i], OutIfaces[i])
	for i := 0; i < len(conf.InIfaces) && i < len(conf.OutIfaces); i++ {
		ensureVeth(conf.InIfaces[i], conf.OutIfaces[i])
	}

	// create veth pair (DispatchVeth, BridgePortVeth) and enslave BridgePortVeth to the RoutingBridge
	ensureVeth(conf.DispatchVeth, conf.BridgePortVeth)

	bridge, bridgeErr := netlink.LinkByName(conf.RoutingBridgeName)
	bridgePort, portErr := netlink.LinkByName(conf.BridgePortVeth)
	switch {
	case bridgeErr != nil:
		logErr("lookup "+conf.RoutingBridgeName, bridgeErr)
	case portErr != nil:
		logErr("lookup "+conf.BridgePortVeth, portErr)
	case bridgePort.Attrs().MasterIndex != bridge.Attrs().Index:
		logErr("enslave "+conf.BridgePortVeth+" to "+conf.RoutingBridgeName,
			netlink.LinkSetMaster(bridgePort, bridge))
	}

	// set all interfaces up (no-op if already up)
	// done before reading MACs: the bridge's MAC can change once a port joins
	all := make([]string, 0, len(conf.InIfaces)+len(conf.OutIfaces)+3)
	all = append(all, conf.InIfaces...)
	all = append(all, conf.OutIfaces...)
	all = append(all, conf.DispatchVeth, conf.BridgePortVeth, conf.RoutingBridgeName)
	for _, name := range all {
		l, err := netlink.LinkByName(name)
		if err != nil {
			logErr("lookup "+name, err)
			continue
		}
		logErr("set "+name+" up", netlink.LinkSetUp(l))
	}

	// get the mac addresses and indices and populate return array with each endpoint: ifaceName -> {Mac, LinkIndex}
	// map order: inIfaces..., outifaces..., dispatchVeth, RoutingBridge
	macIndexMappings := make([]MacIndexMapping, 0, len(conf.InIfaces)+len(conf.OutIfaces)+2)
	var dispatchMac net.HardwareAddr
	ordered := make([]string, 0, len(conf.InIfaces)+len(conf.OutIfaces)+2)
	ordered = append(ordered, conf.InIfaces...)
	ordered = append(ordered, conf.OutIfaces...)
	ordered = append(ordered, conf.DispatchVeth, conf.RoutingBridgeName)
	for _, name := range ordered {
		l, err := netlink.LinkByName(name)
		if err != nil {
			logErr("lookup "+name, err)
			continue // entry missing from the returned map
		}
		attrs := l.Attrs()
		mac := make(net.HardwareAddr, len(attrs.HardwareAddr))
		copy(mac, attrs.HardwareAddr)
		macIndexMappings = append(macIndexMappings, MacIndexMapping{Mac: mac, LinkIndex: uint32(attrs.Index)})
		if name == conf.DispatchVeth {
			dispatchMac = mac
		}
	}

	// create ip neighbor entry for Bogus-IP with lladdr <mac-of-DispatchVeth> nud permanent
	// (ip -6 neigh replace fd00:0:0:37::1 lladdr <mac> dev <BridgePortVeth> nud permanent)
	// NeighSet uses create|replace semantics, so re-running just refreshes the entry.
	if portErr == nil && len(dispatchMac) > 0 {
		logErr("set neighbor "+BOGUS_IPV6, netlink.NeighSet(&netlink.Neigh{
			LinkIndex:    bridgePort.Attrs().Index,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           net.ParseIP(BOGUS_IPV6),
			HardwareAddr: dispatchMac,
		}))
	}

	return macIndexMappings, nil
}