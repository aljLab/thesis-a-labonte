# Hardware-accelerated Programmable targets for Loom
### Thesis A. Labonte @UVA (MNS research group) – M.Sc. Security and Network Engineering

## Driver Code


## SRv6 Proxying
We implement one SRv6 proxy in user space and multiple proxy variants using eBPF.
Find detailed descriptions here:
- [Userspace Go implementation](srv6-proxy/README.md)
- [eBPF implementation(s)](srv6-proxy-ebpf/README.md)

## Experiments
We provide a testing script to evaluate correctness and speed of our implementations using `scapy`.
Find a detailed description and information on its usage [here](experiments/code/README.md).