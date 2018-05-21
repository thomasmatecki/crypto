#!/usr/bin/env bash

openssl ecparam -name secp224r1 -genkey -out ecc.secp224r1.1.enc.priv.pem
openssl ec -in ecc.secp224r1.1.enc.priv.pem -pubout -out ecc.secp224r1.1.enc.pub.pem

openssl ecparam -name secp256r1 -genkey -out ecc.secp256r1.1.sig.priv.pem
openssl ec -in ecc.secp256r1.1.sig.priv.pem -pubout -out ecc.secp256r1.1.sig.pub.pem

openssl genrsa -out rsa.2048.1.enc.priv.pem 2048
openssl rsa -pubout -in rsa.2048.1.enc.priv.pem -out rsa.2048.1.enc.pub.pem

openssl genrsa -out rsa.2048.1.sig.priv.pem 2048
openssl rsa -pubout -in rsa.2048.1.sig.priv.pem -out rsa.2048.1.sig.pub.pem

ssh-keygen -t dsa -b 1024 <<< './dsa'

openssl dsa -in ./dsa -outform pem > dsa.1024.1.sig.priv.pem
openssl dsa -in ./dsa.1024.1.sig.priv.pem -pubout -out dsa.1024.1.sig.pub.pem