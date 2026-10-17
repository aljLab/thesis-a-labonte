# add route for fake gateway with fixed mac address to skip veth ARPing
ip route replace default via 169.254.0.1 dev veth-in onlink table 200
ip neigh replace 169.254.0.1 lladdr 46:bd:b4:d1:d7:f2 dev veth-in nud permanent