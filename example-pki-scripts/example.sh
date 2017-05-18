#!/bin/bash
set -e
./clean.sh
./gen_root_ca.sh capass changeit
# ./gen_node_cert.sh 0 changeit capass && ./gen_node_cert.sh 1 changeit capass &&  ./gen_node_cert.sh 2 changeit capass
./gen_node_cert_openssl.sh "/elasticsearch/OU=UPMC Enterprises/ST=PA/O=UPMC/L=Pittsburgh/C=US" "elasticsearch.elastic.svc.cluster.local" "elasticsearch" changeit capass 
./gen_client_node_cert.sh elasticsearch changeit capass
# ./gen_client_node_cert.sh kirk changeit capass
rm -f ./*tmp*