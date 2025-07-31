#!/bin/bash

# Generate TLS certificates for the admission webhook

set -e

NAMESPACE="admeshion-system"
SERVICE_NAME="admeshion-gateway"
SECRET_NAME="admeshion-gateway-certs"
WEBHOOK_NAME="admeshion-gateway"

ORIGINAL_DIR=$(pwd)
TMPDIR=$(mktemp -d)
cd $TMPDIR

# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -subj "/C=US/ST=CA/L=SF/O=Admeshion/CN=Admeshion CA" -out ca.crt

# Generate server private key
openssl genrsa -out server.key 2048

# Create certificate signing request (CSR)
cat <<EOF > csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

# Generate certificate signing request
openssl req -new -key server.key -subj "/C=US/ST=CA/L=SF/O=Admeshion/CN=${SERVICE_NAME}.${NAMESPACE}.svc" -out server.csr -config csr.conf

# Generate server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile csr.conf

# Create Kubernetes secret
kubectl create secret tls ${SECRET_NAME} \
    --cert=server.crt \
    --key=server.key \
    --namespace=${NAMESPACE} \
    --dry-run=client -o yaml > ${ORIGINAL_DIR}/deploy/kustomize/base/tls-secret.yaml

# Get base64 encoded CA certificate for webhook configuration
CA_BUNDLE=$(base64 -w 0 < ca.crt)

echo "Generated TLS certificates and secret manifest."
echo "CA Bundle for webhook configuration:"
echo $CA_BUNDLE

# Update webhook configuration with CA bundle
sed -i "s/LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K/$CA_BUNDLE/g" ${ORIGINAL_DIR}/deploy/webhook-config.yaml

echo "Updated webhook configuration with CA bundle."

# Cleanup
cd ${ORIGINAL_DIR}
rm -rf $TMPDIR

echo "Certificate generation complete!"
echo "Next steps:"
echo "1. Apply the secret: kubectl apply -f deploy/kustomize/base/tls-secret.yaml"
echo "2. Deploy the gateway: kubectl apply -k deploy/kustomize/base/"
echo "3. Apply the webhook: kubectl apply -f deploy/webhook-config.yaml"
