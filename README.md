# segurança-T5

Iremos subir dois containers. Um rodando o OpenVas e outro com o `Suricata IDS`.
O OpenVas irá escanear o container com o `Suricata` e a IDS irá detectar os Scans do OpenVas.

***

## Introdução

### Container com OpenVas

Para utilizar o OpenVas dentro de um container `Docker` iremos utilizar a imagem `mikesplain/openvas` que já possui o OpenVas instalado e configurado. Entretanto, precisamos atualizar o banco de dados de vulnerabilidades do OpenVas, para isso iremos setar algumas variáveis de ambiente e sincronizar o banco de dados.

`Dockerfile` do container com OpenVas:

```Dockerfile
FROM mikesplain/openvas:latest

ENV FEED=feed.community.greenbone.net
ENV COMMUNITY_NVT_RSYNC_FEED=rsync://$FEED:/nvt-feed
ENV COMMUNITY_CERT_RSYNC_FEED=rsync://$FEED:/cert-data
ENV COMMUNITY_SCAP_RSYNC_FEED=rsync://$FEED:/scap-data
RUN greenbone-nvt-sync
RUN greenbone-certdata-sync
RUN greenbone-scapdata-sync
```

Essa atualização é particularmente demorada, então é interessante que seja feita apenas uma vez, e que o container seja salvo como uma nova imagem.

***

### Container com Suricata

Para utilizar o Suricata dentro de um container `Docker` iremos utilizar a imagem `ubuntu:latest` e instalar o Suricata a partir do repositório oficial. Também iremos instalar algumas ferramentas auxiliares de rede, como `tcpdump` e `iptables`.

`Dockerfile` do container com Suricata:

```Dockerfile
FROM ubuntu:latest

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
```

O container com Suricata será o mesmo que será "atacado" pelo OpenVas, então é importante que ele esteja rodando e com o Suricata configurado antes de rodar o OpenVas.

***

### Ataque escolhido

Por questão de viabilidade, iremos utilizar o `OpenSSH` como serviço vulnerável. A vulnerabilidade escolhida foi a `CVE-2020-15778` que explora uma falha no comando `scp` do `OpenSSH` que permite a execução de comandos arbitrários no servidor.
