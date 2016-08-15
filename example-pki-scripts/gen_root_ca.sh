#!/bin/bash
#./gen_root.sh <organisation name> <root ca passsord> <truststore password>
set -e
rm -rf ca certs* crl *.jks

ORGA_NAME="$1"

if [ -z "$2" ] ; then
  unset CA_PASS TS_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
  read -p "Enter Truststore pass: " -s TS_PASS ; echo
 else
  CA_PASS="$2"
  TS_PASS="$3"
fi

sed -e "s/_RPLC_ORG_NAME/$ORGA_NAME/g" "etc/root-ca.conf" > "etc/gen-root-ca.conf.$ORGA_NAME"
sed -e "s/_RPLC_ORG_NAME/$ORGA_NAME/g" "etc/signing-ca.conf" > "etc/gen-signing-ca.conf.$ORGA_NAME"


mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private

cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

openssl req -new \
    -config "etc/gen-root-ca.conf.$ORGA_NAME" \
    -out ca/root-ca.csr \
    -keyout ca/root-ca/private/root-ca.key \
	-batch \
	-passout "pass:$CA_PASS"
	

openssl ca -selfsign \
    -config "etc/gen-root-ca.conf.$ORGA_NAME" \
    -in ca/root-ca.csr \
    -out ca/root-ca.crt \
    -extensions root_ca_ext \
	-batch \
	-passin "pass:$CA_PASS"
	
echo Root CA generated
	
mkdir -p ca/signing-ca/private ca/signing-ca/db crl certs
chmod 700 ca/signing-ca/private

cp /dev/null ca/signing-ca/db/signing-ca.db
cp /dev/null ca/signing-ca/db/signing-ca.db.attr
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 01 > ca/signing-ca/db/signing-ca.crl.srl

openssl req -new \
    -config "etc/gen-signing-ca.conf.$ORGA_NAME" \
    -out ca/signing-ca.csr \
    -keyout ca/signing-ca/private/signing-ca.key \
	-batch \
	-passout "pass:$CA_PASS"
	
openssl ca \
    -config "etc/gen-root-ca.conf.$ORGA_NAME" \
    -in ca/signing-ca.csr \
    -out ca/signing-ca.crt \
    -extensions signing_ca_ext \
	-batch \
	-passin "pass:$CA_PASS"
	
echo Signing CA generated

openssl x509 -in ca/root-ca.crt -out ca/root-ca.pem -outform PEM
openssl x509 -in ca/signing-ca.crt -out ca/signing-ca.pem -outform PEM
cat ca/signing-ca.pem ca/root-ca.pem > ca/chain-ca.pem

#http://stackoverflow.com/questions/652916/converting-a-java-keystore-into-pem-format

keytool \
    -import \
    -v \
    -keystore truststore.jks   \
    -storepass "$TS_PASS"  \
    -noprompt -alias root-ca-chain \
    -file ca/root-ca.pem
