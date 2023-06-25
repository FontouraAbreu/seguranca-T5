FROM ubuntu:20.04

# Instalando dependencias
RUN apt update && apt install -y \
    software-properties-common

# Instalando Suricata
RUN add-apt-repository -y ppa:oisf/suricata-stable

RUN apt install -y suricata

# Instalando ferramentas auxiliares de rede
RUN apt install -y \
    dnsutils \
    iputils-ping \
    net-tools \
    tcpdump \
    iproute2 \
    iptables

# Utilizando uma configuração local, para facilitar a utilização
COPY ./suricata/ /etc/suricata/

# Atualizando regras a partir das regras locais
RUN suricata-update
RUN suricata -T -c /etc/suricata/suricata.yaml -v

RUN service suricata start

# Instalando pre-requisitos do openssh vulnerável
RUN apt install -y \
    libssl-dev \
    gcc

COPY ./install_vuln.sh /install_vuln.sh

RUN chmod +x /install_vuln.sh

# RUN /install_vuln.sh