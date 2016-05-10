#!/bin/bash
set -e
ORG_NAME="Example Inc."
./clean.sh
./gen_root_ca.sh "$ORG_NAME" "ca pass" "changeit"
./gen_node_cert.sh "$ORG_NAME" "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE" localhost changeit "ca pass" \
           && ./gen_node_cert.sh "$ORG_NAME" "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE" localhost changeit "ca pass" \
           &&  ./gen_node_cert.sh "$ORG_NAME" "CN=node-2.example.com,OU=SSL,O=Test,L=Test,C=DE" localhost changeit "ca pass"
./gen_client_node_cert.sh "$ORG_NAME" "CN=spock,OU=client,O=client,L=Test,C=DE" changeit "ca pass"
./gen_client_node_cert.sh "$ORG_NAME" "CN=kirk,OU=client,O=client,L=Test,C=DE" changeit "ca pass"
echo "Successful"