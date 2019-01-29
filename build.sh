#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/pam_logsentinel.c

# see where pam modules are located. Examples:
# /lib/security/
# /lib/i386-linux-gnu/security/
# /lib/x86_64-linux-gnu/security/
sudo ld -x --shared -o /lib/i386-linux-gnu/security/pam_logsentinel.so pam_logsentinel.o

rm pam_logsentinel.o

# configuration can be anywhere it will be referenced with param
cp logsentinel.conf /etc/security/logsentinel.conf