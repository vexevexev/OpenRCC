#!/bin/sh 
# Script that generates a Certificate Signing Request (CSR) and a temporary 
# certificate for the domain name passed as first argument. 
PROGRAM=`basename $0` 
if [ x$1 = x ]; then 
echo "Script that generates a Certificate Signing Request (CSR) for web 
server certificates" 
echo 
echo "Usage: $PROGRAM <domain>" 
echo 
echo "e.g. $PROGRAM www.example.com" 
exit 1 
fi 
DOMAIN=$1 
echo "Generating random data" 
dd if=/dev/urandom "of=$DOMAIN.random" bs=8k count=100 
echo "Generating encryption key" 
# Use -des3 to encrypt the key with a passphrase 
openssl genrsa -rand "$DOMAIN.random" -out "$DOMAIN.key" 1024 
echo "Generating CSR." 
openssl req -new -key "$DOMAIN.key" -out "$DOMAIN.csr" 
echo "Signing CSR with encryption key" 
openssl x509 -req -days 9999999 -in "$DOMAIN.csr" -signkey "$DOMAIN.key" -out "$DOMAIN-temp.crt" 
rm "$DOMAIN.random"
