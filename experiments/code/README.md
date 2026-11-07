# Validating SRv6 Proxies
Aiming to validate two essential aspects of SRv6 functionality, we create a validation script in python. We aim to validate correctness and speed of the proxy. To this end, we measure if any packets were re-encapsulated incorrectly and measure latency.
To measure latency, we employ `scapy`'s `AsyncSniffer`, which stores a kernel timestamp of packet `tx` or `rx`. We associate incoming and returning packets by using an increasing sequence number as payload. The transmission time is then taken as the difference between the `rx`and `tx` kernel timestamps. We do not validate RTT specifically (although one might to this using this script), because proxy traffic does not usually traverse the proxy twice. 
The script enables running different scenarios, that is packet lists, that are the source of randomized packet picks by the sender. We support SRv6 and non-SRv6 scenarios. For Non-SRv6, IPv4/UDP packets are sent. For SRv6, we offer scenarios with packets from $n$ different of service function chains with $n \in [1, 2, 5, 10]$. For this traffic, we send UDP over IPv4 inside of the Segment Routing header. Since being part of a service function chain can mean multiple different things, especially when talking about SRv6 proxies, we further define what that means in the context of our work.
In the context of the proxy variants we designed (lane-based and correlation based), we differentiate two different ways of identifying SFC membership. Firstly, the segment routing header itself can be used as an identification mechanism: All packets sharing the same SRH belong to the same service chain. It is up to the operator of the whole system to make this notion align with reality. In the first version of our eBPF proxy, we use the segment list of the SRH to classify packets into a service chain. The consequence for this test script is, that in order to send packets belonging to different service chains, we need to vary the SRH, the segment list in particular. We provide packets with 10 different segment lists for this purpose.
Another way of identifying a service chain is by using a set of immutable header fields, which can uniquely identify a service chain. In a simple example, all traffic from subnet A to subnet B might have to pass through Chain C. When classifying packets like this, the contents of the SRH do not matter for SFC classification as they did in the prior example.
Two identical SRHs could be considered different SFCs, if traffic does match source and destination subnets. This might be or might not be desirable. We can not know, which way is better for a specific situation. Consequently, it is up to the user to choose a way of assigning SFC membership. In our testing script, we also want to evaluate proxies using the aforementioned src and dst subnets to categorize packets. To this end, we provide packets with at least 10 distinct (src, dst) pairs. We also use UDP over IPv4 for this.

## Usage
The script runs to threads with `AsyncSniffer`s, which record `tx`and `rx`times. The transmission time is calculated for each packet and persisted after running the test.
The script is packaged with uv, so to run it use: `sudo uv run test.py benchmark [OPTIONS]`
### CLI options
`--send-iface`
The user can specify a send interface, on which the packets are sent out on. This should reach the proxy ingress path eventually. 

`--receive-iface` (optional)
A second interface can be specified to listen for return traffic, the default is using the same interface for ingress and egress.

`--n` 
The number of packets to send to the proxy.

`--inter-pkt-timeout`
The time (in seconds) to wait between sending packets. Default: $0.001$ seconds.

`--scenario`
The scenario flag allows specifying a specific scenario to send packets. Scenarios exist for non-SRv6 (plain IPv4 packets, no service chains) and SRv6 traffic. For SRv6 traffic, we provide alternatives for varying (src, dst) of the inner IP ($n \in [1, 2, 5, 10]$) packet or vary the segment list in the SRH ($n \in [1, 2, 5, 10]$). When using the scenario flag with an unknown scenario, available scenarios are printed. In practice, a scenario is just a list of packets, from which the senders picks randomly to send from.

`--first-hop-mac`
To allow to set a specific mac address for the send ethernet frame, users can use this flag. The value will be set to the mac addr of the receive interface by default.

`--test`
When set, results will only be reported on the CLI and not persisted in `./results`.

`--srv6`
Defaults to true and can be used to disable SRv6 encapsulation, e.g. to get a non-SRv6 baseline.

`--log_string`
A string to add to the persisted results file to distinguish different runs from each other.
