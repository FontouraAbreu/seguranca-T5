FROM ubuntu:latest

RUN apt update && apt install -y \
    software-properties-common

RUN add-apt-repository -y ppa:oisf/suricata-stable

RUN apt install -y suricata

RUN apt install -y \
    dnsutils \
    iputils-ping \
    net-tools \
    tcpdump \
    iproute2 \
    iptables


COPY ./suricata/ /etc/suricata/

RUN suricata-update
RUN suricata -T -c /etc/suricata/suricata.yaml -v
