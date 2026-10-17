//go:build linux

package main

import (
	"log"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/aljLab/thesis-a-labonte/srv6-proxy/setup"
)

type SRv6Header struct {
	Start           [24]byte
	DstAddr         [16]byte
	NextHeader      [1]byte
	HdrExtLen       [1]byte
	RoutingType     [1]byte
	SegmentsLeft    [1]byte
	FirstSeg        [1]byte
	Flags           [1]byte
	Tag             [2]byte
	SegmentList     []byte
	Tlvs            []byte
}

type SRHCache struct {
	Header      SRv6Header
	TotalSize   int
	Mu          sync.Mutex // change to RWLock
}

type SRv6ProxyWorker struct {
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
	VIRTIO_OFFSET = 16
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

	decapWorker := &SRv6ProxyWorker{
		ifaceName: tun0name,
		tunDev:    tun0dev,
		cache:     cache,
	}
	encapWorker := &SRv6ProxyWorker{
		ifaceName: tun1name,
		tunDev:    tun1dev,
		cache:     cache,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		decapWorker.decapTraffic()
	}()

	go func() {
		defer wg.Done()
		encapWorker.encapTraffic()
	}()

	wg.Wait()
}

func (worker *SRv6ProxyWorker) decapTraffic() {
	offset := VIRTIO_OFFSET // make at least room for virtio linux header
	buffSize := 2500 // 65535 //64Kib

	// create one buffer for each (potential) packet, each with offset + max package size (also for writing, GRO)
	// reuse buffers to avoid alloc + copy for each packet
	bufs := make([][]byte, worker.tunDev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset + buffSize)
	}
	sizes := make([]int, worker.tunDev.BatchSize())

	for {
		n, err := worker.tunDev.Read(bufs, sizes, offset)
		if err != nil {
			log.Printf("%s: TUN read failed: %v", worker.ifaceName, err)
			return
		}

		for i := range n {
			packet := bufs[i][offset:offset + sizes[i]]
			if len(packet) == 0 {
				continue
			}

			log.Printf("Read packet with length: %d", len(packet))

			version := packet[0] >> 4
			log.Printf(
				"==> %s: %d bytes, IPv%d",
				worker.ifaceName, len(packet), version,
			)

			if version == 6 {
				nextHeader := packet[6]
				log.Printf("NextHeader: %d", nextHeader)

				// decap SRv6 SRH and cache
				if nextHeader == 43 {
					totalHeaderBytes, _ := worker.processSRv6Header(packet)

					offset = offset + int(totalHeaderBytes) // move offset by the length of outer ipv6 + srh
				} else {
					offset = VIRTIO_OFFSET
				}
			}

			if version == 4{
				src, _ := netip.AddrFromSlice(packet[12:16])
				dst, _ := netip.AddrFromSlice(packet[16:20])
				log.Printf("IPv4 %s ==> %s ", src, dst)
			}
		}
		
		/* packets := make([][]byte, n)
		for i := range n {
			packets[i] = bufs[i][offset:offset+sizes[i]] // offset might have changed if NextHeader == 43
		}
		*/
		log.Println("First Buffer in decap")
		log.Println(bufs[0])
		log.Printf("writing: bufs[0][%d:]", offset)
		log.Println(bufs[0][offset:])
		nWrite, err := worker.tunDev.Write(bufs[:n], offset) // offset might have changed if NextHeader == 43
		if err != nil {
			log.Printf("%s: TUN write failed: %v", worker.ifaceName, err)
			continue
		}

		log.Printf("%s: wrote %d bytes", worker.ifaceName, nWrite)

	}
}

func (worker *SRv6ProxyWorker) encapTraffic(){	
	offset := VIRTIO_OFFSET  // read into bufs with enough space for Virtio + SRv6 header 
	buffSize := 65535 - offset//64Kib, but could be MTU (watch out for GRO)

	bufs := make([][]byte, worker.tunDev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset + buffSize)
	}
	sizes := make([]int, worker.tunDev.BatchSize())

	for {
		log.Printf("Locking cache for reading")
		worker.cache.Mu.Lock()
		totalSize := worker.cache.TotalSize
		header := worker.cache.Header
		worker.cache.Mu.Unlock()

		log.Printf("cached header: {%s, %s, %d, %d, %d, %s, %s}", string(header.Start[:]), string(header.DstAddr[:]), header.NextHeader[0], header.HdrExtLen[0], header.RoutingType, header.SegmentsLeft, header.FirstSeg)

		n, err := worker.tunDev.Read(bufs, sizes, offset + totalSize)
		if err != nil {
			log.Printf("%s: TUN read failed: %v", worker.ifaceName, err)
			return
		}

		for i := range n {
			packet := bufs[i][offset : offset + totalSize + sizes[i]]
			if len(packet) == 0 {
				continue
			}

			version := packet[0] >> 4
			log.Printf(
				"<== %s: %d bytes, IPv%d",
				worker.ifaceName, len(packet), version,
			)

			if version == 4{
				src, _ := netip.AddrFromSlice(packet[12:16])
				dst, _ := netip.AddrFromSlice(packet[16:20])
				log.Printf("IPv4 %s ==> %s ", src, dst)
			}

			// copy the cached header into the buffer head room |---Free(virtio)---|------SRv6------|------Packet------|
			copy(bufs[i][VIRTIO_OFFSET:VIRTIO_OFFSET+totalSize], header.ToByte())

		}
		
		/* packets := make([][]byte, n)
		for i := range n {
			// write packet buff: |------SRv6 Header----|--Packet-------------------------------|
			packets[i] = append(header.ToByte(totalSize), bufs[i][offset : offset + sizes[i]]...)
		}*/

		log.Printf("Header Bytes%s", string(header.ToByte()))

		log.Printf("offset=%d len=%d first=%#x ver=%d", VIRTIO_OFFSET, len(bufs[0]), bufs[0][0], bufs[0][0]>>4)
		nWrite, err := worker.tunDev.Write(bufs[:n], VIRTIO_OFFSET) // write to tun file with virtio offset
		if err != nil {
			log.Printf("%s: TUN write failed: %v", worker.ifaceName, err)
			continue
		}

		log.Printf("%s: wrote %d bytes", worker.ifaceName, nWrite)

	}
}

func (w *SRv6ProxyWorker) processSRv6Header(packet []byte) (byte, error) {
	start := packet[:24]
	_ = packet[24:40]
	innerNextHeader := packet[40:41]
	hdrExtLen := packet[41:42] // length of segments + options in 8-octets
	routingType := packet[42:43]
	segmentsLeft := packet[43:44] // points to active segment
	lastIndex := packet[44:45] // = FirstSegment
	flags := packet[45:46]
	tag := packet[46:48]

	segmentList := make([][]byte, lastIndex[0] + 1)
	offset := 48
	for i := range segmentList {
		k := offset + i * 16
		segmentList[i] = packet[k:k+16]
	}

	// decrement segmentsLeft
	// copy segmentList[segmentsLeft] into dst of outer
	activeSID := segmentsLeft[0] - 1
	totalHeaderBytes := hdrExtLen[0] * 8 + byte(48)
	segmentListEndOffset := 48 + len(segmentList) * 16

	log.Printf("totalHeaderBytes: %d (should be 48 + )", totalHeaderBytes)

	updatedHeader := SRv6Header{
		Start: [24]byte(start),
		DstAddr: [16]byte(segmentList[activeSID]),
		NextHeader: [1]byte(innerNextHeader),
		HdrExtLen: [1]byte(hdrExtLen),
		RoutingType: [1]byte(routingType),
		SegmentsLeft: [1]byte{activeSID}, // is already byte
		FirstSeg: [1]byte(lastIndex),
		Flags: [1]byte(flags),
		Tag: [2]byte(tag),
		SegmentList: packet[48:segmentListEndOffset],
		Tlvs: packet[segmentListEndOffset:],
	}
	log.Printf("Locking Cache for writing")
	w.cache.Mu.Lock()
	w.cache.Header = updatedHeader
	w.cache.TotalSize = int(totalHeaderBytes)
	w.cache.Mu.Unlock()
	log.Printf("Unlocked Cache for writing")
	log.Printf("cached header: {%d, %d, %d, %d, %d, %d, %d, TLVs: %d}", updatedHeader.Start[:], updatedHeader.DstAddr[:], updatedHeader.NextHeader[0], updatedHeader.HdrExtLen[0], updatedHeader.RoutingType, updatedHeader.SegmentsLeft, updatedHeader.FirstSeg, updatedHeader.Tlvs)
	log.Printf("w.cache.Header.ToByte(): %d", w.cache.Header.ToByte())
	// return the total length of the header
	return totalHeaderBytes, nil
}

func (h *SRv6Header) ToByte() []byte {
	bits := append(h.Start[:], h.DstAddr[:]...)
	bits = append(bits, h.NextHeader[0])
	bits = append(bits, h.HdrExtLen[0])
	bits = append(bits, h.RoutingType[0])
	bits = append(bits, h.SegmentsLeft[0])
	bits = append(bits, h.FirstSeg[0])
	bits = append(bits, h.Flags[0])
	bits = append(bits, h.Tag[:]...)
	bits = append(bits, h.SegmentList...)
	bits = append(bits, h.Tlvs...)
	log.Printf("Returning header (w/o TLVs): %d", bits)
	return bits
}
