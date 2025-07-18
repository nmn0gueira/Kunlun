#!/bin/bash

set -euo pipefail

install_dir="${1:-$(pwd)/openssl}"

cd /tmp
curl -L https://github.com/openssl/openssl/releases/download/openssl-3.0.17/openssl-3.0.17.tar.gz -o openssl-3.0.17.tar.gz
tar -xzf openssl-3.0.17.tar.gz
cd openssl-3.0.17
sed -i '211s/\<static\>//' crypto/ec/curve25519.c
./Configure no-shared enable-ec_nistp_64_gcc_128 no-ssl2 no-ssl3 no-comp --prefix="${install_dir}"
make depend 
make install_sw

echo "OpenSSL 3.0.17 installed to: ${install_dir}"