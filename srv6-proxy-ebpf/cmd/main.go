
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

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

const (
	cachedValueSize = 2096 // lock + len + pad + IPv6 header + max SRH
)

type config struct {
    iml0       string
    toVNF      []string
    fromVNF    []string
    gatewayMAC string
}

func main() {
	// TODO: fetch gateway mac
	version := flag.Int("version", 1, "Determines which version of the proxy file to use.")

	flag.Parse()
	filePath := "pkg/ebpf/proxy.c"

	fmt.Println("Version: ", *version)
	if *version == 2 {
		filePath = "pkg/ebpf/proxyv2.c"
		fmt.Println("running versino 2 with filepath: ", filePath)
	}

    cfg := config{
        iml0: "iml0",

        toVNF:   []string{"veth-in0", "veth-in1"},
        fromVNF: []string{"veth-out0", "veth-out1"},

        gatewayMAC: "02:00:00:00:00:01",
    }

    ifaceIML, err := net.InterfaceByName(cfg.iml0)
    if err != nil {
        log.Fatal(err)
    }

    toVNF := make([]*net.Interface, len(cfg.toVNF))
    fromVNF := make([]*net.Interface, len(cfg.fromVNF))

    for i, name := range cfg.toVNF {
        toVNF[i], err = net.InterfaceByName(name)
        if err != nil {
            log.Fatal(err)
        }
    }

    for i, name := range cfg.fromVNF {
        fromVNF[i], err = net.InterfaceByName(name)
        if err != nil {
            log.Fatal(err)
        }
    }

    gatewayMAC, err := net.ParseMAC(cfg.gatewayMAC)
    if err != nil || len(gatewayMAC) != 6 {
        log.Fatal("gatewayMAC must be a valid 6-byte MAC address")
    }

    n := len(toVNF)
    ctx := context.Background()

    tmp, err := os.MkdirTemp("", "ebpf-proxy-*")
    if err != nil {
        log.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    baseObj := filepath.Join(tmp, "base.o")
    compileBPF(ctx, filePath, baseObj, n, 0)

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
		os.Exit(-1);
	} else {
		log.Printf("Load error: %+v", err)
		defer base.Close()
	}

    srhMap := base.Maps["srh_table"]
    linkMap := base.Maps["link_index_table"]
    macMap := base.Maps["mac_addr_table"]
    // scratchMap := base.Maps["mac_addr_table"]

    if srhMap == nil || linkMap == nil || macMap == nil {
        log.Fatal("expected BPF maps are missing")
    }

    // All maps are populated before attaching any program.
    zeroValue := make([]byte, cachedValueSize)
    for i := 0; i < n; i++ {
        if err := srhMap.Put(uint32(i), zeroValue); err != nil {
            log.Fatal("initialize SRH entry: ", err)
        }
    }

    // Link-index keys 0..n-1 point to the toVNF interfaces.
    for i, iface := range toVNF {
        if err := linkMap.Put(uint32(i), uint32(iface.Index)); err != nil {
            log.Fatal("populate toVNF link index: ", err)
        }

        if err := macMap.Put(uint32(i), paddedMAC(iface.HardwareAddr)); err != nil {
            log.Fatal("populate toVNF MAC: ", err)
        }
    }

    // Mac keys n..2n-1 point to the fromVNF interfaces.
    for i, iface := range fromVNF {
        if err := macMap.Put(uint32(n + i), paddedMAC(iface.HardwareAddr)); err != nil {
            log.Fatal("populate toVNF MAC: ", err)
        }
    }
	/**
	* Special Keys
	*/
    // iml0
    if err := linkMap.Put(uint32(2*n), uint32(ifaceIML.Index)); err != nil {
        log.Fatal("populate iml0 link index: ", err)
    }

    if err := macMap.Put(uint32(2*n), paddedMAC(ifaceIML.HardwareAddr)); err != nil {
        log.Fatal("populate iml0 MAC: ", err)
    }

    // gateway mac for return traffic
    if err := macMap.Put(uint32(2*n+1), paddedMAC(gatewayMAC)); err != nil {
        log.Fatal("populate gateway MAC: ", err)
    }

	// scratch map initialization
	// zero value of size 
	/* if err := scratchMap.Put(uint32(20), [20]byte{}); err != nil {
		log.Fatal("init scratch 0able: ", err)
	} */

	/*
    * Attach decap to iml0
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

    decapLink, err := link.AttachXDP(link.XDPOptions{
        Program:   decapProg,
        Interface: ifaceIML.Index,
    })
    if err != nil {
        log.Fatal("attach decap: ", err)
    }
    links = append(links, decapLink)

    replacements := map[string]*ebpf.Map{
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
			log.Printf("Load error: %+v", err)
		}

        links = append(links, l)

        fmt.Printf(
            "encap slot %d attached to %s (ifindex %d)\n",
            i, iface.Name, iface.Index,
        )
    }

    fmt.Printf(
        "decap attached to %s; shared maps initialized for %d slots\n",
        ifaceIML.Name, n,
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
