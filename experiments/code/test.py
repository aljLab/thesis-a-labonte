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
from cyclopts import App

from scapy.all import Ether, Raw, IPv6, IPv6ExtHdrSegmentRouting, Udp, AsyncSniffer, sendp


app = App()

INTER_PACKET_TIMEOUT = 0.01
CAPTURE_STARTUP_TIMEOUT = 0.5
RECEIVE_TIMEOUT = 1

BOGUS_MAC = "02:00:00:00:00:2"
SEGMENT_LIST = ["2001:db8:3::1","2001:db8:2::1"]

SRC_MAC = None
DST_MAC = None

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

    printf(f"Successfully benchmarked with {n} packets ({send_iface} --> {receive_iface}, srv6: {srv6})")


def run_bench(n:int, send_iface:str, receive_iface:str, srv6:bool, pending:any, results:any):
    lock = threading.Lock()
    received = threading.Event()

    filter = f""

    sniffer = AsyncSniffer(
        iface=receive_iface,
        prn=packet_received,
        store=False,
        filter=filter
    )


    SRC_MAC = netifaces.ifaddresses(send_iface)[netifaces.AF_LINK][0]["addr"]
    DST_MAC = netifaces.ifaddresses(receive_iface)[netifaces.AF_LINK][0]["addr"]

    sniffer.start()
    time.sleep(CAPTURE_STARTUP_TIMEOUT)

    try:
        for seq in range(n):
            payload = seq.to_bytes(8, "little")

            if srv6:
                # assuming that send_iface == recv_iface for proxy testing
                pkt = (
                    Ether(src=BOGUS_MAC, dst=DST_MAC) / 
                    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
                    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST, segleft=len(SEGMENT_LIST)-1, lastentry=len(SEGMENT_LIST)-1) / 
                    IPv6(src="fd00::1", dst="fd00::2") / 
                    Udp(sport=12345, dport=12346) / 
                    Raw(load=payload)
                )
            else:
                pkt = (
                    Ether(src=SRC_MAC, dst=DST_MAC) /
                    IPv6(src="fd00::1", dst="fd00::2") /
                    Udp(sport=12345, dport=12346) /
                    Raw(load=payload)
                )
            
            tx = time.perf_couter_ns()

            with lock:
                pending[seq] = tx
            
            sendp(pkt, iface=send_iface, verbose=False)

            time.sleep(INTER_PACKET_TIMEOUT)
    finally:
        time.sleep(RECEIVE_TIMEOUT)
        sniffer.stop()


def packet_received(pkt):
    if not pkt.haslayer(Ether):
        print("Received malformed packet, aborting.")
        return
    
    if pkt.Ether.dst is not DST_MAC:
        print("Received packet not addressed correctly, aborting.")
        return
    
    if not pkt.haslayer(Raw):
        print("No sequence number received, aborting.")
        return
    
    seq = int.from_bytes(pkt[Raw].load[:8], "little")

    rx = time.perf_counter_ns()

    with lock:
        if seq in pending:
            tx = pending.pop(seq)
            rtt_ns = rx - tx
            results.append(rtt_ns)
            received.set()


def store_results(results:any, n, srv6, log_string):
    if not results:
        print("No results to store.")
        return
    
    kind = "proxy" if srv6 else "base"
    t = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H:%M:%S")
    file_path = f"results/{kind}_{f"{log_string}_" if log_string != "" else ""}{n}_{t}.csv"
    with open(file_path, "w", newline="") as f:
        writer = csv.Writer(f)
        writer.writerow(results)


def report_results(results:any):
    if not results:
        print("No results to report.")
        return
    
    us = [ x / 1000 for x in results]

    print("\nResults")
    print("------------------")
    print(f"Received:   {len(results)}")
    print(f"Average:    {statistics.mean(us):.2f}")
    print("------------------")

if __name__ == "__main__":
    app()