#!/bin/bash

wget https://openbsd.c3sl.ufpr.br/pub/OpenBSD/OpenSSH/portable/

tar -xvf openssh-8.3p1.tar.gz
cd openssh-8.3p1
./configure