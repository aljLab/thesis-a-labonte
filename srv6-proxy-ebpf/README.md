The SRv6 proxy implementation in eBPF uses several XDP programs.
It implements a dynamic proxy and matches return traffic based on the return interface (fromVNF). The proxy needs to be configured with a set of interface pairs, one `toVNF` and one `fromVNF`. Each tuple represents a lane. One lane isolates one SRv6 context at a time. The context is needed to correctly re-encapsulate packets after a network function can perform arbitrary modifications to packet fields.
It is important that the mapping between interface tuples is correct: the VNF must adhere to the mapping (i.e. forward traffic received from `toVNFi` to `fromVNFi`), and the eBPF maps need to be correctly populated from user space. Maps are used by the `toVNF` pipeline to identify the correct link index to redirect a packet to (requires correct map: $lane \rightarrow linkIndex$). The lane is assigned based on packet properties, the SRH in particular.
The `fromVNF` pipeline retrieves the correct lane (which encodes the lookup key for the cached header) from a map based on the interface a packet is received. Note that the incoming interface is determined by the redirect decision made by the `toVNF` pipeline. A map ($linkIndex \rightarrow lane$) is required to map the link index of the receiving interface to the correct lane.
Three XDP programs are used to classify, decapsulate and re-encapsulate SRv6 traffic traversing the proxy.
## Setup
To test the proxy, build and `cmd/main.go`. This will set up a routing bridge, several veth-interface pairs cosplaying as legacy VNFs, and a veth pair connecting a dispatcher to the routing bridge (one peer is enslaved to the bridge).
Note that when using veths, XDP might not be advertised/enabled, which would lead to `xdp_redirect` errors. To make a veth-peer (e.g. the dispatcher veth-peer) accept XDP redirects, one can enable `gro` on the other veth-peer. 

> Enabling gro creates a ring buffer and NAPI instance, into which the XDP redirect buffer can be written and consumed by.

The main program loads the eBPF collections and attaches them to the correct interfaces.
It also populates maps with the correct information. For testing/development the coupling of interfaces is decided from the order in the declaration.
![ebpf-proxy](ebpf-proxy.png)

### Testing
To see the proxy in action, listen with `tcpdump` on the veth peer attached to the bridge and send SRv6 packets using scapy.
```
p = Ether()/IPv6(src="2001:db8:1::1", dst="2001:db8:2::1")/IPv6ExtHdrSegmentRouting(addresses=["2001:db8:3::1","2001:db8:2::1"], segleft=1, lastentry=1)/IPv6(src="fd00::1", dst="fd00::2")/ICMPv6EchoRequest()
sendp(p, iface="routing-br-port")
```

### Troubleshooting
If no traffic arrives, the XDP redirect might fail. Check with `sudo bpftrace -e 'tracepoint:xdp:xdp_redirect_err {printf("redirect_error")}'`. Enabling gro on the veth-peer enslaved to the routing bridge might solve it.
If IPv4 traffic is dropped, check `rp_filter` and `accept_local` for interfaces involved.
## Programs

### `classify_sfc`
This program is the entry point into the toVNF pipeline. It classifies the packet into a lane and passes this decision to the decap program via packet meta data and a tail call.
The tail call is also used to reduce complexity in the decap program.
The classification mechanism uses a cache, storing the segments characterizing a service chain, and compares the SRH of incoming packets with the cached per-lane entries. If one entry matches, it puts the incoming packet into the same lane.
If a free lane is encountered, the packet is put there immediately to maximize utilization.
If all lanes are occupied, the lane with the oldest SFC is evicted and the new packet assigned to its lane.
A monotonic clock increasing with each packet is used to establish a notion of packet age.
After determining a lane, the packet is passed to the decap program (tailcall) passing the assigned lane along in `xdp_md.data_meta`.
In the test environment the `classify_sfc` program is attached to the dispatcher veth peer.
### `decap`
The `decap` program decapsulates the packet, updates, and caches the header. It also updates the ethernet header to be addressed to its corresponding `fromVNF` interface. Otherwise the packet might be dropped if the interface is not in promiscuous mode.

### `encap`
The `encap` program looks up the correct lane (and header to put back on the packet) based on the interface index on which the packet is received.
It fetches the cached header, copies it in front of the inner packet and updates fields int the ethernet header and SRH to match the inner packet.
It then redirects the packet through the dispatcher veth peer, which leads to the packet being received by the routing bridge.

> `bpf_redirect()` in XDP only supports emitting packets on the egress queue of interfaces, hence "redirecting" a packet means "putting it out through". In TC, packets can be directly redirected to the ingress queue of another interface.



