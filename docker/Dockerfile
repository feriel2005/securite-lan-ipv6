FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping iputils-tracepath traceroute net-tools \
    tcpdump tshark ndisc6 nftables bridge-utils procps \
    radvd frr isc-dhcp-relay isc-dhcp-client kea-dhcp6-server \
    python3 python3-scapy \
    ca-certificates curl nano less \
 && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

