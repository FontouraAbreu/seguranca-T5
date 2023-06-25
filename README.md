# segurança-T5

Iremos subir dois containers. Um rodando o `OpenVas` e outro com o `Suricata IDS`.
O `OpenVas` irá escanear o container com o `Suricata` e a IDS irá detectar os Scans do `OpenVas`.

***

## Introdução

### Container com OpenVas

Para utilizar o `OpenVas` dentro de um container `Docker` iremos utilizar a imagem `mikesplain/openvas` que já possui o `OpenVas` instalado e configurado. Entretanto, precisamos atualizar o banco de dados de vulnerabilidades do `OpenVas`, para isso iremos setar algumas variáveis de ambiente e sincronizar o banco de dados.

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

RUN service suricata start
```

Com o `Suricata` rodando, podemos testar as regras padrão utilizando o comando:

```bash
curl http://testmynids.org/uid/index.html
```

enquanto observamos o log do Suricata:

```bash
tail -f /var/log/suricata/fast.log
```

Será possível ver o seguinte alerta:

```bash
06/24/2023-17:03:41.271088  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 65.8.214.24:80 -> 172.18.0.2:42414
```

***

### Ataque escolhido

Por questão de viabilidade, iremos utilizar o `OpenSSH` como serviço vulnerável. A vulnerabilidade escolhida foi a `CVE-2020-15778` que explora uma falha no comando `scp` do `OpenSSH` que permite a execução de comandos arbitrários no servidor.

Para garantir que o serviço estará vulnerável, iremos utilizar uma versão antiga do `OpenSSH` que possui a vulnerabilidade.######

Vamos utilizar o `Dockerfile` do container com Suricata para instalar o `OpenSSH` e configurar o serviço.

```Dockerfile


Para explorar essa vulnerabilidade, iremos utilizar o exploit disponível em `https://github.com/Neko-chanQwQ/CVE-2020-15778-Exploit` que foi desenvolvido em `Python`.
