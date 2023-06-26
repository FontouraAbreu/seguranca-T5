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

# Copiando regra do scp
COPY ./suricata/rules/scp.rules /var/lib/suricata/rules/scp.rules

# Instalando pre-requisitos do openssh vulnerável
RUN apt install -y \
    libssl-dev \
    zlib1g-dev \
    build-essential \
    gcc

# Instalando openssh vulnerável
COPY ./install_vuln.sh /install_vuln.sh
RUN chmod +x /install_vuln.sh
RUN /install_vuln.sh
EXPOSE 22


# criando um usuario de exemplo
RUN useradd -m -d /home/gregio -s /bin/bash gregio
RUN echo 'gregio:gregio' | chpasswd

COPY exploit.sh /exploit.sh

RUN chmod +x /exploit.sh
