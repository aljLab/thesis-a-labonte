// go:build linux
package main

import (
	"context"
	"errors"
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

const (
	cachedValueSize = 2104 // lock + len + pad + IPv6 header + max SRH + routingHdr
)

func main() {
	filePath := "pkg/ebpf/proxyv3.c"

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

    fmt.Printf("Compiling programs\n")
    // compile the ebpf programs
    baseObj := filepath.Join(tmp, "base.o")
    compileBPF(ctx, filePath, baseObj, n)

    // load the collection spec
    spec, err := ebpf.LoadCollectionSpec(baseObj)
    if err != nil {
        log.Fatal("load base spec: ", err)
    }

    // create Collection with high log level
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
    fmt.Printf("Is err really nil: %s? is base not nil %s?\n", err, base)
    fmt.Printf("Created Collection, no verifier errors... Trying to defer closing the collection\n")

    defer base.Close()

    // shared maps
    srhMap := base.Maps["srh_table"]
    linkMap := base.Maps["link_index_table"]
    macMap := base.Maps["mac_addr_table"]
    laneMap := base.Maps["lane_table"]
    tailcallMap := base.Maps["progs"]

    // per CPU / per target maps
    // clockMap := base.Maps["clock_map"]
    sfcLaneMap := base.Maps["sfc_lane_map"]

    if srhMap == nil || linkMap == nil || macMap == nil {
        log.Fatal("expected shared BPF maps are missing")
    }

    if sfcLaneMap == nil {
        log.Fatal("expected per CPU BPF maps are missing")
    }

    // All maps are populated before attaching any program.
    zeroValue := make([]byte, cachedValueSize)
    for i := 0; i < n; i++ {
        if err := srhMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("initialize SRH entry: ", err)
        }
    }

    log.Printf("\nMacIndexMap %s\n", macIndexMappings)


    // Link-index keys 0..n-1 point to the toVNF interfaces.
    for i, iface := range macIndexMappings {
        // inIfaces..., OutIfaces..., DispatchVeth, RoutingBridge
        // put LinkIndex in correct spot in LinIndex
        if err := linkMap.Put(uint32(i), uint32(iface.LinkIndex)); err != nil {
            log.Fatal("populate lane LinkIndex: ", err)
        }
        // put mac addr in correct place in macMap
        if err := macMap.Put(uint32(i), paddedMAC(iface.Mac)); err != nil {
            log.Fatal("populate lane MAC: ", err)
        }
        n_lanes := len(macIndexMappings)/2 - 1
        if(i >= n_lanes && i < 2*n_lanes){ // indeces n -> 2n-1 are outgoing interfaces
            err := laneMap.Put(uint32(iface.LinkIndex), uint32(i - n_lanes)); if err != nil {
                log.Fatal("populating lane map (link_index of return iface -> lane): ", err)
            }
        }
    }

    // init clock map
    /* if err := clockMap.Put(uint32(0), uint64(0)); err != nil {
        log.Fatal("populating clock map: ", err)
    } */

    // init per cpu map
    zeroValue = make([]byte, 2064)
    for i := range n {
        if err := sfcLaneMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("populating sfc lane map: ", err)
        }
    }

    decapProg := base.Programs["decap"]
    // init prog map
    err = tailcallMap.Put(uint32(0), decapProg); if err != nil {
        log.Fatal("populating tailcall map: ", err)
    }

    fmt.Println("Initialized all map values\n")

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

    fmt.Println("Succesfully attached prog to dispatch interface\n")

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

    // TODO: consider pinning here (storing the file descriptor to keep the objects from being gc'ed)
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

