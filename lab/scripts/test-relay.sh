#!/bin/sh
R=clab-ipv6lab-router
docker exec $R sh -c 'pkill tcpdump; rm -f /tmp/in.pcap /tmp/out.pcap'
docker exec -d $R sh -c 'tcpdump -U -ni eth1 -w /tmp/in.pcap udp port 547'
docker exec -d $R sh -c 'tcpdump -U -ni eth2 -w /tmp/out.pcap udp port 547'
sleep 2
docker exec clab-ipv6lab-victim1 timeout 8 dhclient -6 -v eth1
docker exec $R pkill tcpdump
sleep 1
echo "=== IN (eth1) ===";  docker exec $R tcpdump -nr /tmp/in.pcap
echo "=== OUT (eth2) ==="; docker exec $R tcpdump -nr /tmp/out.pcap
