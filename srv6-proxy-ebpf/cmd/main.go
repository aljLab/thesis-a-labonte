// go:build linux
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/aljLab/srv6-proxy-ebpf/pkg/utils"
	"github.com/aljLab/srv6-proxy-ebpf/setup"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Proto struct {
    Name string
    Number int
}

const (
	cachedValueSize = 2104 // lock + len + pad + IPv6 header + max SRH + routingHdr
    SRH_TABLE_HASH_MAP_SIZE = 128
    SRH_HASH_KEY_SIZE = 60
)

func main() {
    var laneBased bool
    flag.BoolVar(&laneBased, "lane-based", true, "Indicate to use lane-based proxying.")
    flag.Parse()

    if laneBased {
        runLaneBasedProxy()
    } else {
        runCorrelationBasedProxy()
    }
}

func runCorrelationBasedProxy(){
    fmt.Println("Field-based Proxy: Running Setup...")
    filePath := "pkg/ebpf/field_based_srv6_proxy.c"

	conf := setup.Config{
        InIfaces: []string{"bf-in"},
        OutIfaces: []string{"bf-out"},
        BridgePortVeth: "br-port",
        DispatchVeth: "bf-port",
        RoutingBridgeName: "routing-bridge",
    }

    macIndexMappings, err := setup.Setup(&conf); if err != nil {
        log.Fatalf("Could not setup networking: %s", err)
    }

    n := len(conf.InIfaces)
    ctx := context.Background()

    tmp, err := os.MkdirTemp("", "ebpf-proxy-*")
    if err != nil {
        log.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    baseObj := filepath.Join(tmp, "base.o")
    compileBPF(ctx, filePath, baseObj, n)

    spec, err := ebpf.LoadCollectionSpec(baseObj)
    if err != nil {
        log.Fatal("load base spec: ", err)
    }

    base, err := ebpf.NewCollectionWithOptions(
		spec,
		ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogLevel: ebpf.LogLevelInstruction |
						ebpf.LogLevelBranch |
						ebpf.LogLevelStats,
				},
            },
	)
    
    var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Printf("Verifier log (%d lines):\n", len(ve.Log))
		fmt.Println(strings.Join(ve.Log, "\n"))
		os.Exit(-1)
	} else {
        if err != nil {
            log.Fatalf("Error when creating collection: %s", err);
        }
    }

    defer base.Close()

    // shared maps
    srhMap := base.Maps["srh_table"]
    linkMap := base.Maps["link_index_table"]
    macMap := base.Maps["mac_addr_table"]
    l3MaskMap := base.Maps["mask_table_l3"]
    l4MaskMap := base.Maps["mask_table_l4"]
    scratchMap := base.Maps["scratch_table"]

    if srhMap == nil || linkMap == nil || macMap == nil || l3MaskMap == nil || l4MaskMap == nil || scratchMap == nil {
        log.Fatal("expected shared BPF maps are missing")
    }

    zeroValue := make([]byte, cachedValueSize)
    if err := scratchMap.Put(uint32(0), zeroValue); err != nil {
        log.Fatal("initialize SRH scratch table entry: ", err)
    }

    // Link-index keys 0..n-1 point to the toVNF interfaces.
    for i, iface := range macIndexMappings {
        // inIfaces..., OutIfaces..., DispatchVeth, RoutingBridge
        if err := linkMap.Put(uint32(i), uint32(iface.LinkIndex)); err != nil {
            log.Fatal("populate lane LinkIndex: ", err)
        }
        if err := macMap.Put(uint32(i), paddedMAC(iface.Mac)); err != nil {
            log.Fatal("populate lane MAC: ", err)
        }
    }
    
    supportedL3Protos := []Proto{{Name: "ipv4", Number: 4}, { Name: "ipv6", Number: 6}}

    mockFieldsMap := make(map[string][]utils.ImmutableHeaderField)
    mockFieldsMap["ipv4"] = utils.MockIPv4ImmutableHdrFields
    mockFieldsMap["ipv6"] = utils.MockIPv6ImmutableHdrFields
    mockFieldsMap["tcp"] = utils.MockTcpImmutableHdrFields
    mockFieldsMap["udp"] = utils.MockUdpImmutableHdrFields

    for _, proto := range supportedL3Protos {
        mask, err := utils.GetKeyMaskForProto(mockFieldsMap[proto.Name]); if err != nil {
            fmt.Printf("Could not get key mask for IPv4: %s", err)
        }
        err = l3MaskMap.Put(uint32(proto.Number), utils.L3KeyMask{ Bytes: [utils.MAX_L3_HDR_LEN]byte(mask) }); if err != nil {
            log.Fatalf("Could not insert key mask for proto %s.\n", proto.Name)
        }
    }

    supportedL4Protocols := []Proto{{ Name: "tcp", Number: 6 }, { Name: "udp", Number: 17}}

    for _, proto := range supportedL4Protocols {
        mask, err := utils.GetKeyMaskForProto(mockFieldsMap[proto.Name]); if err != nil {
            fmt.Printf("Could not get key mask for IPv6: %s", err)
        }
        err = l4MaskMap.Put(uint32(proto.Number), utils.L4KeyMask{ Bytes: [utils.MAX_L4_HDR_LEN]byte(mask) }); if err != nil {
            log.Fatalf("Could not insert key mask for protocol %s.\n", proto.Name)
        }
    }

	/*
    * Attach decap to dispatcher
	*/

    ingressProg := base.Programs["proxy_ingress"]
    if ingressProg == nil {
        log.Fatal("decap program missing")
    }

    decapIndex := macIndexMappings[2*n].LinkIndex
    decapLink, err := link.AttachXDP(link.XDPOptions{
        Program:   ingressProg,
        Interface: int(decapIndex),
    })
    if err != nil {
        log.Fatal("attach ingress prog: ", err)
    }

    defer decapLink.Close()

    /*
    * ENCAP
    */

    encapIface := macIndexMappings[1] // with n = 1, 

    encapProg := base.Programs["proxy_egress"]
    if encapProg == nil {
        log.Fatalf("Did not find encap program.")
    }

    encapLink, err := link.AttachXDP(link.XDPOptions{
        Program:   encapProg,
        Interface: int(encapIface.LinkIndex),
    })

    if errors.As(err, &ve) {
        fmt.Printf("Verifier log (%d lines):\n", len(ve.Log))
        fmt.Println(strings.Join(ve.Log, "\n"))
    } else {
        if err != nil {
            log.Fatalf("attach encap to %d: %v", encapIface.LinkIndex, err)
        }
    }
    defer encapLink.Close()

    fmt.Printf(
        "decap attached to ifaceIndex %d; Field-based Proxy running now.\n",
        decapIndex,
    )

    select {}
}

func runLaneBasedProxy(){
    fmt.Println("Lane-based Proxy: Setting up...")
    filePath := "pkg/ebpf/lane_based_srv6_proxy.c"

	conf := setup.Config{
        InIfaces: []string{"bf-00", "bf-10", "bf-20", "bf-30"},
        OutIfaces: []string{"bf-01", "bf-11", "bf-21", "bf-31"},
        BridgePortVeth: "routing-br-port",
        DispatchVeth: "dispatcher",
        RoutingBridgeName: "routing-bridge",
    }

    macIndexMappings, err := setup.Setup(&conf); if err != nil {
        log.Fatalf("Could not setup networking: %s", err)
    }
    defer setup.CleanUpNetworkingSetup(&conf)

    fmt.Printf("Set Up Networking\n")

    n := len(conf.InIfaces)
    ctx := context.Background()

    tmp, err := os.MkdirTemp("", "ebpf-proxy-*")
    if err != nil {
        log.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    baseObj := filepath.Join(tmp, "base.o")
    compileBPF(ctx, filePath, baseObj, n)

    spec, err := ebpf.LoadCollectionSpec(baseObj)
    if err != nil {
        log.Fatal("load base spec: ", err)
    }

    base, err := ebpf.NewCollectionWithOptions(
		spec,
		ebpf.CollectionOptions{
            Programs: ebpf.ProgramOptions{
                LogLevel: ebpf.LogLevelInstruction |
                    ebpf.LogLevelBranch |
                    ebpf.LogLevelStats,
            },
        },
	)
    
    // check verifier errors
    var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Printf("Verifier log (%d lines):\n", len(ve.Log))
		fmt.Println(strings.Join(ve.Log, "\n"))
		os.Exit(-1)
	} else {
        if err != nil {
            log.Fatalf("Error when creating collection: %s", err);
        }
    }

    defer base.Close()

    // shared maps
    srhMap := base.Maps["srh_table"]
    linkMap := base.Maps["link_index_table"]
    macMap := base.Maps["mac_addr_table"]
    laneMap := base.Maps["lane_table"]
    tailcallMap := base.Maps["progs"]

    sfcLaneMap := base.Maps["sfc_lane_map"]

    if srhMap == nil || linkMap == nil || macMap == nil {
        log.Fatal("expected shared BPF maps are missing")
    }

    if sfcLaneMap == nil {
        log.Fatal("expected per CPU BPF maps are missing")
    }

    zeroValue := make([]byte, cachedValueSize)
    for i := 0; i < n; i++ {
        if err := srhMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("initialize SRH entry: ", err)
        }
    }

    // Link-index keys 0..n-1 point to the toVNF interfaces.
    for i, iface := range macIndexMappings {
        // inIfaces..., OutIfaces..., DispatchVeth, RoutingBridge
        if err := linkMap.Put(uint32(i), uint32(iface.LinkIndex)); err != nil {
            log.Fatal("populate lane LinkIndex: ", err)
        }
        if err := macMap.Put(uint32(i), paddedMAC(iface.Mac)); err != nil {
            log.Fatal("populate lane MAC: ", err)
        }
        n_lanes := len(macIndexMappings)/2 - 1
        if(i >= n_lanes && i < 2*n_lanes){ // indices n -> 2n-1 are outgoing interfaces
            err := laneMap.Put(uint32(iface.LinkIndex), uint32(i - n_lanes)); if err != nil {
                log.Fatal("populating lane map (link_index of return iface -> lane): ", err)
            }
        }
    }

    zeroValue = make([]byte, 2072) // 2064 /w lock
    for i := range n {
        if err := sfcLaneMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("populating sfc lane map: ", err)
        }
    }

    decapProg := base.Programs["decap"]
    err = tailcallMap.Put(uint32(0), decapProg); if err != nil {
        log.Fatal("populating tailcall map: ", err)
    }

	/*
    * Attach decap to dispatcher
	*/

    classifyProg := base.Programs["classify_sfc"]
    if classifyProg == nil {
        log.Fatal("decap program missing")
    }

    var links []link.Link
    defer func() {
        for _, l := range links {
            _ = l.Close()
        }
    }()

    decapIndex := macIndexMappings[2*n].LinkIndex
    decapLink, err := link.AttachXDP(link.XDPOptions{
        Program:   classifyProg,
        Interface: int(decapIndex),
    })
    if err != nil {
        log.Fatal("attach classify prog (-> tailcall to decap): ", err)
    }
    links = append(links, decapLink)


    var encapCollections []*ebpf.Collection
    defer func() {
        for _, c := range encapCollections {
            c.Close()
        }
    }()
    
    for j, iface := range macIndexMappings {
        if(j >= n && j < 2*n){
            prog := base.Programs["encap"]
            if prog == nil {
                log.Fatal("encap program missing")
            }

            l, err := link.AttachXDP(link.XDPOptions{
                Program:   prog,
                Interface: int(iface.LinkIndex),
            })

            var ve *ebpf.VerifierError
            if errors.As(err, &ve) {
                fmt.Printf("Verifier log (%d lines):\n", len(ve.Log))
                fmt.Println(strings.Join(ve.Log, "\n"))
            } else {
                if err != nil {
                    log.Fatalf("attach encap to %d: %v", iface.LinkIndex, err)
                }
            }
            fmt.Printf("Succesfully attached prog to fromVNF interface %d\n", j)
            links = append(links, l)
        }
    }

    fmt.Printf(
        "decap attached to ifaceIndex %d; shared maps initialized for %d lanes\n",
        decapIndex, n,
    )

    select {}
}

func paddedMAC(mac net.HardwareAddr) []byte {
    if len(mac) != 6 {
        log.Fatalf("expected a 6-byte MAC address, got %d bytes", len(mac))
    }

    value := make([]byte, 8)
    copy(value[:6], mac)
    return value
}

func compileBPF(
    ctx context.Context,
    source string,
    output string,
    n int,
) {
    archInclude, targetArch := targetConfig()

    args := []string{
        "-O2",
        "-g",
        "-target", "bpf",
        "-D" + targetArch,
        "-DN=" + strconv.Itoa(n),
        "-I" + archInclude,
        "-c", source,
        "-o", output,
    }

    clang := os.Getenv("CLANG")
    if clang == "" {
        clang = "clang"
    }

    cmd := exec.CommandContext(ctx, clang, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Run(); err != nil {
        log.Fatalf("compile %s: %v", output, err)
    }
}

func targetConfig() (includeDir, define string) {
    switch runtime.GOARCH {
    case "amd64":
        return "/usr/include/x86_64-linux-gnu", "__TARGET_ARCH_x86"
    case "arm64":
        return "/usr/include/aarch64-linux-gnu", "__TARGET_ARCH_arm64"
    default:
        log.Fatalf("unsupported build architecture: %s", runtime.GOARCH)
        return "", ""
    }
}

