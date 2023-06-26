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

enquanto observamos o log do Suricata:

```bash
tail -f /var/log/suricata/fast.log
```

Podemos testar as regras padrão do `Suricata` utilizando o comando:

```bash
curl http://testmynids.org/uid/index.html
```

Será possível ver o seguinte alerta:

```bash
06/24/2023-17:03:41.271088  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 65.8.214.24:80 -> 172.18.0.2:42414
```

***

## Scans do OpenVas

Para realizar os scans do `OpenVas` através da interface web, iremos setar um `Alvo` no `OpenVas` com o IP do container com o `Suricata` e depois iremos configurar uma `Task` que ira realizar o scan conforme configurado.

Iremos configurar 3 `Tasks` diferentes, uma para cada tipo de scan:

- Full and fast
- Full and very deep
- CVE scan

Com o objetivo de testar a eficácia do `Suricata` e também para testar a eficácia do `OpenVas` em detectar vulnerabilidades.

### Ataque escolhido

Por questão de viabilidade, iremos utilizar o `OpenSSH` como serviço vulnerável. A vulnerabilidade escolhida foi a `CVE-2020-15778` que explora uma falha no comando `scp` do `OpenSSH`. A vulnerabilidade permite a execução de comandos arbitrários no servidor.

Para garantir que o serviço estará vulnerável, iremos utilizar a versão `8.3p1` do `OpenSSH` que possui a vulnerabilidade.

***

### Configurando a vulnerabilidade

Vamos utilizar o um **script** no container com `Suricata` para instalar o `OpenSSH` e configurar o serviço.

```bash
# criando usuario sshd e pasta para privsep
mkdir /var/lib/sshd
chmod -R 700 /var/lib/sshd/
chown -R root:sys /var/lib/sshd/
useradd -r -U -d /var/lib/sshd/ -c "sshd privsep" -s /bin/false sshd

# baixando o openssh
wget https://openbsd.c3sl.ufpr.br/pub/OpenBSD/OpenSSH/portable/openssh-8.3p1.tar.gz

# descompactando e instalando
tar -xvf openssh-8.3p1.tar.gz
cd openssh-8.3p1
./configure --with-md5-passwords --with-privsep-path=/var/lib/sshd/ --sysconfdir=/etc/ssh 

make
make install
```

Para explorar essa vulnerabilidade, iremos utilizar o exploit disponível em `https://github.com/Neko-chanQwQ/CVE-2020-15778-Exploit` que foi desenvolvido em `Python`.

***

## Como o ataque funciona

A `CVE-2020-15778` explora a **falta de sanitização** no comando `scp` do `OpenSSH`, em específico no caracter **backtick**. A manipulação do argumento de destino do comando `scp` permitindo a execução de comandos com **privilégios incorretos** na máquina de destino.

Os mantenedores do `OpenSSH` reportaram que a **falta de sanitização era intencional**, visto que caso fosse feita a sanitização, a correção poderia **quebrar muitos scripts** que utilizam o comando `scp`.

***

## Regra no Suricata para detectar o ataque

Para permitir que o suricata detecte o ataque, vamos configurar uma nova regra em `/etc/suricata/rules/scp.rules`:

```bash
echo "alert tcp any any -> any any (msg:"SCP Command Detected"; flow:to_server,established; content:"scp"; nocase; sid:1000001; rev:1;)" >> /etc/suricata/rules/scp.rules
```

Além disso, precisamos atualizar o arquivo `/etc/suricata/suricata.yaml` para que o Suricata utilize a nova regra:

```yaml
rule-files:
  - /etc/suricata/rules/scp.rules
```

Dessa forma, o Suricata irá detectar qualquer comando `scp` que for executado.

### Testando a nova regra

Podemos testar a nova regra utilizando o comando `scp`, enquanto observamos o log do Suricata:

```bash
tail -f /var/log/suricata/fast.log
```

rodando:

```bash
touch teste
scp teste gregio@172.18.0.2:/tmp/teste
```

***

## Configurando Scan no OpenVas

### Scan específico para a vulnerabilidade

***

## Pacotes do ataque

***

## Alerta gerado pelo Suricata

***

## Como executar

### Iniciando os serviços

Para iniciar os containers, precisamos executar o `docker compose`:

```bash
docker compose up -d
```

Após alguns minutos os dois containers estarão rodando e o `OpenVas` estará atualizado. Para abrir o dashboard do `OpenVas` basta acessar `https://localhost:443` e fazer login com o usuário `admin` e senha `admin`.

### Iniciando o `Suricata`

Para iniciar o `Suricata`, precisamos entrar no container `ids` e executar o comando:

```bash
service suricata start
```

### Iniciando o OpenSSH vulnerável

Para iniciar o `OpenSSH` vulnerável, precisamos entrar no container `ids` e executar o comando:

```bash
/usr/local/sbin/sshd -D &
```

Para executar o ataque, basta entrar no container `ids` e executar o script `exploit.sh`:

```bash
./exploit.sh
```
