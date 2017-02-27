#!/bin/bash
set -e
./clean.sh
./gen_root_ca.sh capass changeit
./gen_node_cert.sh 0 changeit capass && ./gen_node_cert.sh 1 changeit capass &&  ./gen_node_cert.sh 2 changeit capass
./gen_node_cert_openssl.sh "/CN=abc/OU=SSL/O=Test/L=Test/C=DE" "*.example.com" nodex changeit capass 
./gen_client_node_cert.sh spock changeit capass
./gen_client_node_cert.sh kirk changeit capass