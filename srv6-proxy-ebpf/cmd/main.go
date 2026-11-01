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

    "github.com/aljLab/srv6-proxy-ebpf/setup"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

const (
	cachedValueSize = 2104 // lock + len + pad + IPv6 header + max SRH + routingHdr
)

func main() {
	filePath := "pkg/ebpf/proxyv2.c"

	conf := setup.Config{
        InIfaces: []string{"bf-00", "bf-10"},
        OutIfaces: []string{"bf-01", "bf-11"},
        BridgePortVeth: "routing-br-port",
        DispatchVeth: "dispatcher",
        RoutingBridgeName: "routing-bridge",
    }

    macIndexMap, err := setup.Setup(&conf); if err != nil {
        log.Fatalf("Could not setup networking: %s", err)
    }

    fmt.Printf("Set Up Networking")

    n := len(conf.InIfaces)
    ctx := context.Background()

    tmp, err := os.MkdirTemp("", "ebpf-proxy-*")
    if err != nil {
        log.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    fmt.Printf("Compiling programs")
    // compile the ebpf programs
    baseObj := filepath.Join(tmp, "base.o")
    compileBPF(ctx, filePath, baseObj, n, 0)

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
	}

    defer base.Close()

    // shared maps
    srhMap := base.Maps["srh_table"]
    linkMap := base.Maps["link_index_table"]
    macMap := base.Maps["mac_addr_table"]

    // per CPU / per target maps
    clockMap := base.Maps["clock_map"]
    sfcLaneMap := base.Maps["sfc_lane_map"]

    if srhMap == nil || linkMap == nil || macMap == nil {
        log.Fatal("expected shared BPF maps are missing")
    }

    if clockMap == nil || sfcLaneMap == nil {
        log.Fatal("expected per CPU BPF maps are missing")
    }

    fmt.Println("Fetched all maps")

    // All maps are populated before attaching any program.
    zeroValue := make([]byte, cachedValueSize)
    for i := 0; i < n; i++ {
        if err := srhMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("initialize SRH entry: ", err)
        }
    }

    // Link-index keys 0..n-1 point to the toVNF interfaces.
    i := 0
    for _, iface := range macIndexMap {
        // inIfaces..., OutIfaces..., DispatchVeth, RoutingBridge
        // put LinkIndex in correct spot in LinIndex
        if err := macMap.Put(uint32(i), uint32(iface.LinkIndex)); err != nil {
            log.Fatal("populate lane LinkIndex: ", err)
        }
        // put mac addr in correct place in macMap
        if err := macMap.Put(uint32(i), paddedMAC(iface.Mac)); err != nil {
            log.Fatal("populate lane MAC: ", err)
        }
        i++
    }

    // init clock map
    if err := clockMap.Put(uint32(0), uint64(0)); err != nil {
        log.Fatal("populating clock map: ", err)
    }

    // init per cpu map
    zeroValue = make([]byte, 16)
    for i := range n {
        if err := sfcLaneMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("populating sfc lane map: ", err)
        }
    }

    fmt.Println("Initialized all map values")

	/*
    * Attach decap to dispatcher
	*/

    decapProg := base.Programs["decap"]
    if decapProg == nil {
        log.Fatal("decap program missing")
    }

    var links []link.Link
    defer func() {
        for _, l := range links {
            _ = l.Close()
        }
    }()
    decapIndex := macIndexMap[conf.DispatchVeth].LinkIndex
    decapLink, err := link.AttachXDP(link.XDPOptions{
        Program:   decapProg,
        Interface: int(decapIndex),
    })
    if err != nil {
        log.Fatal("attach decap: ", err)
    }
    links = append(links, decapLink)

    fmt.Println("Succesfully attached prog to dispatch interface")

/*     replacements := map[string]*ebpf.Map{
        "srh_table":       srhMap,
        "link_index_table": linkMap,
        "mac_addr_table":  macMap,
    }

    var encapCollections []*ebpf.Collection
    defer func() {
        for _, c := range encapCollections {
            c.Close()
        }
    }()
    for i, iface := range fromVNF {
        obj := filepath.Join(tmp, fmt.Sprintf("encap-%d.o", i))

        // compile program again, passing in the index of each fromVNF interface (nf(i/2)) for correct SRH lookup
        compileBPF(ctx, filePath, obj, n, i)

        encapSpec, err := ebpf.LoadCollectionSpec(obj)
        if err != nil {
            log.Fatalf("load encap spec %d: %v", i, err)
        }

        // instantiate collection with newly compiled program referencing map objects created earlier
        coll, err := ebpf.NewCollectionWithOptions(
            encapSpec,
            ebpf.CollectionOptions{
                MapReplacements: replacements,
                Programs: ebpf.ProgramOptions{
                    LogLevel: ebpf.LogLevelInstruction |
                        ebpf.LogLevelBranch |
                        ebpf.LogLevelStats,
                },
            },
        )
        if err != nil {
            log.Fatalf("load encap collection %d: %v", i, err)
        }
        // store for later cleanup
        encapCollections = append(encapCollections, coll)

        prog := coll.Programs["encap"]
        if prog == nil {
            log.Fatalf("encap program missing for slot %d", i)
        }

        l, err := link.AttachXDP(link.XDPOptions{
            Program:   prog,
            Interface: iface.Index,
        })
        if err != nil {
            log.Fatalf("attach encap to %s: %v", iface.Name, err)
        }
        var ve *ebpf.VerifierError
        if errors.As(err, &ve) {
            fmt.Printf("Verifier log (%d lines):\n", len(ve.Log))
            fmt.Println(strings.Join(ve.Log, "\n"))
        } else {
            log.Printf("No load err")
        }

        links = append(links, l)

        fmt.Printf(
            "encap slot %d attached to %s (ifindex %d)\n",
            i, iface.Name, iface.Index,
        )
    } */

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
    ifaceIndex int,
) {
    archInclude, targetArch := targetConfig()

    args := []string{
        "-O2",
        "-g",
        "-target", "bpf",
        "-D" + targetArch,
        "-DN=" + strconv.Itoa(n),
        "-DSLOT=" + strconv.Itoa(ifaceIndex),
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
