# use scapy to send packets and timestamp reception on an interface
# run configurations:
#   - n -> packet count
#   - send-iface, receive-iface (if omitted received on the same interface -> matching dst mac addr)
#   - srv6 (default: false) -> send SRv6 traffic out of send-iface
import time
from datetime import datetime, timezone
import threading
import csv
import netifaces
import statistics
import os
from cyclopts import App
from functools import partial

from scapy.all import Ether, Raw, IPv6, IPv6ExtHdrSegmentRouting, UDP, AsyncSniffer, sendp


app = App()

INTER_PACKET_TIMEOUT = 0.01
CAPTURE_STARTUP_TIMEOUT = 0.5
RECEIVE_TIMEOUT = 1

BOGUS_MAC = "02:00:00:00:00:02"
SEGMENT_LIST = ["2001:db8:3::1","2001:db8:2::1"]

lock = threading.Lock()
received = threading.Event()

@app.command
def benchmark(
    n=10000, 
    send_iface = None,
    receive_iface = None,
    srv6 = False,
    log_string = ""
    ):
    ''' Benchmark a proxy solution by sending packets through it using scapy.
        Args:   
            n (int): Number of packets to send
            send_iface (str): Name of the interface to put out scapy packets on.
            receive_iface (str): Name of the interface to listen on for return traffic.
            srv6 (bool): Flag indicating whether or not to use SRv6 packets (might not be sensible for non-SRv6 baseline).
            log_string (str): string to append to the stored results file to differentiate test conditions unknown to the script.
    '''
    if not send_iface:
        print("sending interface is required. Usage: uv run test.py benchmark --send-iface 'eth0'")
        return
    
    if not receive_iface:
        receive_iface = send_iface
    
    pending = {}
    results = []

    run_bench(n, send_iface, receive_iface, srv6, pending, results)

    store_results(results, n, srv6, log_string)

    report_results(results)

    print(f"Successfully benchmarked with {n} packets ({send_iface} --> {receive_iface}, srv6: {srv6})")


def run_bench(n:int, send_iface:str, receive_iface:str, srv6:bool, pending:any, results:any):

    src_mac = netifaces.ifaddresses(send_iface)[netifaces.AF_LINK][0]["addr"]
    dst_mac = netifaces.ifaddresses(receive_iface)[netifaces.AF_LINK][0]["addr"]

    send_handler = partial(packet_outbound, pending=pending, lock=lock)
    recv_handler = partial(packet_received, dst_mac=dst_mac.lower(), pending=pending, results=results, lock=lock)

    send_sniffer = AsyncSniffer(
        iface=send_iface,
        prn=send_handler,
        store=False,
        filter="outbound"
    )

    return_sniffer = AsyncSniffer(
        iface=receive_iface,
        prn=recv_handler,
        store=False,
        filter="inbound"
    )

    send_sniffer.start()
    return_sniffer.start()
    time.sleep(CAPTURE_STARTUP_TIMEOUT)

    try:
        for seq in range(n):
            payload = seq.to_bytes(8, "little")

            if srv6:
                # assuming that send_iface == recv_iface for proxy testing
                pkt = (
                    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
                    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
                    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST, segleft=len(SEGMENT_LIST)-1, lastentry=len(SEGMENT_LIST)-1) / 
                    IPv6(src="fd00::1", dst="fd00::2") / 
                    UDP(sport=12345, dport=12346) / 
                    Raw(load=payload)
                )
            else:
                pkt = (
                    Ether(src=src_mac, dst=dst_mac) /
                    IPv6(src="fd00::1", dst="fd00::2") /
                    UDP(sport=12345, dport=12346) /
                    Raw(load=payload)
                )
            
            sendp(pkt, iface=send_iface, verbose=False)

            time.sleep(INTER_PACKET_TIMEOUT)
    finally:
        time.sleep(RECEIVE_TIMEOUT)
        if send_sniffer.running:
            send_sniffer.stop()
        if return_sniffer.running:
            return_sniffer.stop()


def packet_received(pkt, dst_mac, pending, results, lock):
    if not pkt.haslayer(Ether):
        return
    
    #if pkt[Ether].dst.lower() != dst_mac:
    #    print("Mac mismatch in inbound")
    #    return
    
    if not pkt.haslayer(Raw):
        return
    
    seq = int.from_bytes(pkt[Raw].load[:8], "little")

    rx = pkt.time
    print("rx inbound: ", rx)

    with lock:
        if seq in pending:
            tx = pending.pop(seq)
            results.append(rx - tx)
            # received.set()


def packet_outbound(pkt, pending, lock):
    tx = pkt.time
    print("tx outbound: ", tx)
    if not pkt.haslayer(Ether):
        return
    
    if not pkt.haslayer(Raw):
        return
    
    seq = int.from_bytes(pkt[Raw].load[:8], "little")

    with lock:
        pending[seq] = tx


def store_results(results, n, srv6, log_string):
    if not results:
        print("No results to store.")
        return
    
    kind = "proxy" if srv6 else "base"
    t = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    infix = f"{log_string}_" if log_string != "" else ""
    file_path = f"{kind}_{infix}{n}_{t}.csv"
    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["rtt_ns"])
        writer.writerows([r] for r in results)


def report_results(results):
    if not results:
        print("No results to report.")
        return
    
    us = [ x / 1000 for x in results]

    print("\nResults")
    print("------------------------")
    print(f"Received:         {len(results)}")
    print(f"Average(µs):  {statistics.mean(us):.8f}")
    print("------------------------")

if __name__ == "__main__":
    app()