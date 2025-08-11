#!/bin/bash

# SSL Certificate Generation Script for Secure Fullstack App
# This script generates self-signed certificates for development
# For production, use Let's Encrypt or commercial certificates

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CERT_DIR="./certs"
KEY_FILE="$CERT_DIR/private.key"
CERT_FILE="$CERT_DIR/certificate.crt"
CSR_FILE="$CERT_DIR/certificate.csr"
CONFIG_FILE="$CERT_DIR/openssl.conf"

# Default values
COUNTRY="US"
STATE="State"
CITY="City"
ORGANIZATION="Secure Fullstack App"
ORGANIZATIONAL_UNIT="IT"
COMMON_NAME="localhost"
VALIDITY_DAYS=365
KEY_SIZE=2048

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  SSL Certificate Generator${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if OpenSSL is installed
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL is not installed. Please install OpenSSL first."
        exit 1
    fi
    print_status "OpenSSL found: $(openssl version)"
}

# Function to create certificate directory
create_cert_dir() {
    if [ ! -d "$CERT_DIR" ]; then
        mkdir -p "$CERT_DIR"
        print_status "Created certificate directory: $CERT_DIR"
    else
        print_status "Certificate directory exists: $CERT_DIR"
    fi
}

# Function to create OpenSSL configuration
create_openssl_config() {
    cat > "$CONFIG_FILE" << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req
x509_extensions = v3_req

[dn]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
OU = $ORGANIZATIONAL_UNIT
CN = $COMMON_NAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $COMMON_NAME
DNS.2 = localhost
DNS.3 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    print_status "Created OpenSSL configuration: $CONFIG_FILE"
}

# Function to generate private key
generate_private_key() {
    if [ -f "$KEY_FILE" ]; then
        print_warning "Private key already exists: $KEY_FILE"
        read -p "Do you want to overwrite it? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Keeping existing private key"
            return
        fi
    fi

    print_status "Generating private key..."
    openssl genrsa -out "$KEY_FILE" $KEY_SIZE
    chmod 600 "$KEY_FILE"
    print_status "Private key generated: $KEY_FILE"
}

# Function to generate certificate signing request
generate_csr() {
    print_status "Generating certificate signing request..."
    openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CONFIG_FILE"
    print_status "CSR generated: $CSR_FILE"
}

# Function to generate self-signed certificate
generate_self_signed_cert() {
    print_status "Generating self-signed certificate..."
    openssl req -x509 -nodes -days $VALIDITY_DAYS -key "$KEY_FILE" -out "$CERT_FILE" -config "$CONFIG_FILE"
    chmod 644 "$CERT_FILE"
    print_status "Self-signed certificate generated: $CERT_FILE"
}

# Function to generate certificate for Let's Encrypt
generate_letsencrypt_cert() {
    print_status "Generating certificate for Let's Encrypt..."
    openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CONFIG_FILE"
    print_status "CSR generated for Let's Encrypt: $CSR_FILE"
    print_warning "Use this CSR with Let's Encrypt or your CA"
}

# Function to verify certificate
verify_certificate() {
    if [ -f "$CERT_FILE" ]; then
        print_status "Verifying certificate..."
        openssl x509 -in "$CERT_FILE" -text -noout | head -20
        print_status "Certificate verification completed"
    else
        print_error "Certificate file not found: $CERT_FILE"
    fi
}

# Function to display certificate information
show_cert_info() {
    if [ -f "$CERT_FILE" ]; then
        print_status "Certificate Information:"
        echo "Subject: $(openssl x509 -in "$CERT_FILE" -noout -subject)"
        echo "Issuer: $(openssl x509 -in "$CERT_FILE" -noout -issuer)"
        echo "Valid From: $(openssl x509 -in "$CERT_FILE" -noout -startdate)"
        echo "Valid Until: $(openssl x509 -in "$CERT_FILE" -noout -enddate)"
        echo "Serial Number: $(openssl x509 -in "$CERT_FILE" -noout -serial)"
    fi
}

# Function to create development certificate
create_dev_cert() {
    print_header
    print_status "Creating development certificate..."
    
    check_openssl
    create_cert_dir
    create_openssl_config
    generate_private_key
    generate_self_signed_cert
    verify_certificate
    show_cert_info
    
    print_status "Development certificate created successfully!"
    print_warning "This is a self-signed certificate for development only."
    print_warning "For production, use Let's Encrypt or commercial certificates."
}

# Function to create production certificate
create_prod_cert() {
    print_header
    print_status "Creating production certificate..."
    
    check_openssl
    create_cert_dir
    create_openssl_config
    generate_private_key
    generate_letsencrypt_cert
    
    print_status "Production certificate setup completed!"
    print_status "Next steps:"
    echo "1. Use the CSR file with Let's Encrypt:"
    echo "   certbot certonly --csr $CSR_FILE"
    echo "2. Or submit the CSR to your CA"
    echo "3. Place the received certificate in $CERT_FILE"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  dev     Generate self-signed certificate for development"
    echo "  prod    Generate CSR for production (Let's Encrypt)"
    echo "  verify  Verify existing certificate"
    echo "  info    Show certificate information"
    echo "  help    Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  COUNTRY              Country code (default: US)"
    echo "  STATE                State/Province (default: State)"
    echo "  CITY                 City (default: City)"
    echo "  ORGANIZATION         Organization name (default: Secure Fullstack App)"
    echo "  COMMON_NAME          Common name (default: localhost)"
    echo "  VALIDITY_DAYS        Certificate validity in days (default: 365)"
    echo "  KEY_SIZE             RSA key size (default: 2048)"
    echo ""
    echo "Examples:"
    echo "  $0 dev"
    echo "  $0 prod"
    echo "  COMMON_NAME=example.com $0 dev"
}

# Main script logic
case "${1:-help}" in
    "dev")
        create_dev_cert
        ;;
    "prod")
        create_prod_cert
        ;;
    "verify")
        verify_certificate
        ;;
    "info")
        show_cert_info
        ;;
    "help"|*)
        show_usage
        ;;
esac 