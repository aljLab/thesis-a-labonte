
 //go:build linux

package main

import (
	"log"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/aljLab/thesis-a-labonte/srv6-proxy/setup"
)

type IPv6Header struct {
	Raw []byte
}

type SRHeader struct {
	Raw []byte
}

type SRHCache struct {
	outerHeader IPv6Header
	srh         SRHeader
	mu          sync.Mutex
}

type SRv6ProxyWriter struct {
	ifaceName string
	tunDev    tun.Device
	cache     *SRHCache
}

type SRv6ProxyReader struct {
	ifaceName string
	tunDev    tun.Device
	cache     *SRHCache
}

const (
	tun0 = "tun0"
	tun1 = "tun1"
	MTU  = 1294
)

func main() {
	// Create TUN devices
	tun0dev, err := tun.CreateTUN(tun0, MTU)
	if err != nil {
		log.Fatalf("create tun0: %v", err)
	}
	defer tun0dev.Close()

	tun1dev, err := tun.CreateTUN(tun1, MTU)
	if err != nil {
		tun0dev.Close()
		log.Fatalf("create tun1: %v", err)
	}
	defer tun1dev.Close()

	// get names of actual interfaces
	tun0name, err := tun0dev.Name()
	if err != nil {
		log.Fatalf("get tun0 name: %v", err)
	}
	
	tun1name, err := tun1dev.Name()
	if err != nil {
		log.Fatalf("get tun1 name: %v", err)
	}

	// Set up all interfaces tun0, tun1, decap4, for devel: veth-pair
	setup.SetupLinks(tun0name, tun1name)

	// ensure the system allows srv6 and vrf
	setup.ConfigureSysctls(tun0name, tun1name)

	// add routes for development:
	// 10.0.10.0/24 encap seg6 mode encap segs 2 [ fd00:2 fd00:3 ] dev tun0
	// table 200: default dev veth-in
	// table 201: default dev tun1
	// fd::03 encap seg6local action END.DT4 vrftable main dev decap4 table 202
	setup.SetupRoutesAndRules(tun0name, tun1name)

	cache := &SRHCache{}

	reader0 := &SRv6ProxyReader{
		ifaceName: tun0name,
		tunDev:    tun0dev,
		cache:     cache,
	}
	reader1 := &SRv6ProxyReader{
		ifaceName: tun1name,
		tunDev:    tun1dev,
		cache:     cache,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		readAndLogTun0Traffic(reader0)
	}()

	go func() {
		defer wg.Done()
		readAndLogTun1Traffic(reader1)
	}()

	wg.Wait()
}

func readAndLogTun0Traffic(reader *SRv6ProxyReader) {
	readAndLogTraffic(reader, "TUN0 - Inwards ==>")
}

func readAndLogTun1Traffic(reader *SRv6ProxyReader) {
	readAndLogTraffic(reader, "TUN1 - Outwards <==")
}

func readAndLogTraffic(reader *SRv6ProxyReader, prefix string) {
	bufs := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)

	for {
		n, err := reader.tunDev.Read(bufs, sizes, 0)
		if err != nil {
			log.Printf("%s: TUN read failed: %v", reader.ifaceName, err)
			return
		}

		for i := 0; i < n; i++ {
			packet := bufs[i][:sizes[i]]
			if len(packet) == 0 {
				continue
			}

			version := packet[0] >> 4

			log.Printf(
				"%s %s: %d bytes, IPv%d",
				prefix, reader.ifaceName, len(packet), version,
			)

			// TODO: Parse packet and update/use reader.cache.
		}
	}
}
