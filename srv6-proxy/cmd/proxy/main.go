
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
	// Create TUN devices.
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

	// Set up the other development interfaces.
	// SetupLinks must no longer create tun0 or tun1.
	setup.SetupLinks()

	tun0name, err := tun0dev.Name()
	if err != nil {
		log.Fatalf("get tun0 name: %v", err)
	}

	tun1name, err := tun1dev.Name()
	if err != nil {
		log.Fatalf("get tun1 name: %v", err)
	}

	setup.ConfigureSysctls(tun0name, tun1name)
	setup.SetupRoutesAndRules(tun0name, tun1name)

	// One shared cache for both directions.
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
	// WireGuard's TUN API reads batches of packets.
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
