#!/bin/bash

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