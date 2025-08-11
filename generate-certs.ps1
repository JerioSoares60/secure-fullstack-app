# SSL Certificate Generation Script for Secure Fullstack App (PowerShell)
# This script generates self-signed certificates for development
# For production, use Let's Encrypt or commercial certificates

param(
    [Parameter(Position=0)]
    [ValidateSet("dev", "prod", "verify", "info", "help")]
    [string]$Action = "help"
)

# Configuration
$CERT_DIR = "./certs"
$KEY_FILE = "$CERT_DIR/private.key"
$CERT_FILE = "$CERT_DIR/certificate.crt"
$CSR_FILE = "$CERT_DIR/certificate.csr"
$CONFIG_FILE = "$CERT_DIR/openssl.conf"

# Default values
$COUNTRY = $env:COUNTRY ?? "US"
$STATE = $env:STATE ?? "State"
$CITY = $env:CITY ?? "City"
$ORGANIZATION = $env:ORGANIZATION ?? "Secure Fullstack App"
$ORGANIZATIONAL_UNIT = $env:ORGANIZATIONAL_UNIT ?? "IT"
$COMMON_NAME = $env:COMMON_NAME ?? "localhost"
$VALIDITY_DAYS = $env:VALIDITY_DAYS ?? "365"
$KEY_SIZE = $env:KEY_SIZE ?? "2048"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Header {
    param([string]$Message)
    Write-Host "================================`n  $Message`n================================" -ForegroundColor Blue
}

# Function to check if OpenSSL is installed
function Test-OpenSSL {
    try {
        $opensslVersion = openssl version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "OpenSSL found: $opensslVersion"
            return $true
        }
    }
    catch {
        Write-Error "OpenSSL is not installed. Please install OpenSSL first."
        return $false
    }
    return $false
}

# Function to create certificate directory
function New-CertificateDirectory {
    if (-not (Test-Path $CERT_DIR)) {
        New-Item -ItemType Directory -Path $CERT_DIR -Force | Out-Null
        Write-Status "Created certificate directory: $CERT_DIR"
    }
    else {
        Write-Status "Certificate directory exists: $CERT_DIR"
    }
}

# Function to create OpenSSL configuration
function New-OpenSSLConfig {
    $configContent = @"
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
"@

    $configContent | Out-File -FilePath $CONFIG_FILE -Encoding ASCII
    Write-Status "Created OpenSSL configuration: $CONFIG_FILE"
}

# Function to generate private key
function New-PrivateKey {
    if (Test-Path $KEY_FILE) {
        Write-Warning "Private key already exists: $KEY_FILE"
        $overwrite = Read-Host "Do you want to overwrite it? (y/N)"
        if ($overwrite -notmatch "^[Yy]$") {
            Write-Status "Keeping existing private key"
            return
        }
    }

    Write-Status "Generating private key..."
    openssl genrsa -out $KEY_FILE $KEY_SIZE
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Private key generated: $KEY_FILE"
    }
    else {
        Write-Error "Failed to generate private key"
        exit 1
    }
}

# Function to generate certificate signing request
function New-CertificateSigningRequest {
    Write-Status "Generating certificate signing request..."
    openssl req -new -key $KEY_FILE -out $CSR_FILE -config $CONFIG_FILE
    if ($LASTEXITCODE -eq 0) {
        Write-Status "CSR generated: $CSR_FILE"
    }
    else {
        Write-Error "Failed to generate CSR"
        exit 1
    }
}

# Function to generate self-signed certificate
function New-SelfSignedCertificate {
    Write-Status "Generating self-signed certificate..."
    openssl req -x509 -nodes -days $VALIDITY_DAYS -key $KEY_FILE -out $CERT_FILE -config $CONFIG_FILE
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Self-signed certificate generated: $CERT_FILE"
    }
    else {
        Write-Error "Failed to generate certificate"
        exit 1
    }
}

# Function to generate certificate for Let's Encrypt
function New-LetsEncryptCertificate {
    Write-Status "Generating certificate for Let's Encrypt..."
    openssl req -new -key $KEY_FILE -out $CSR_FILE -config $CONFIG_FILE
    if ($LASTEXITCODE -eq 0) {
        Write-Status "CSR generated for Let's Encrypt: $CSR_FILE"
        Write-Warning "Use this CSR with Let's Encrypt or your CA"
    }
    else {
        Write-Error "Failed to generate CSR for Let's Encrypt"
        exit 1
    }
}

# Function to verify certificate
function Test-Certificate {
    if (Test-Path $CERT_FILE) {
        Write-Status "Verifying certificate..."
        openssl x509 -in $CERT_FILE -text -noout | Select-Object -First 20
        Write-Status "Certificate verification completed"
    }
    else {
        Write-Error "Certificate file not found: $CERT_FILE"
    }
}

# Function to display certificate information
function Show-CertificateInfo {
    if (Test-Path $CERT_FILE) {
        Write-Status "Certificate Information:"
        Write-Host "Subject: $(openssl x509 -in $CERT_FILE -noout -subject)"
        Write-Host "Issuer: $(openssl x509 -in $CERT_FILE -noout -issuer)"
        Write-Host "Valid From: $(openssl x509 -in $CERT_FILE -noout -startdate)"
        Write-Host "Valid Until: $(openssl x509 -in $CERT_FILE -noout -enddate)"
        Write-Host "Serial Number: $(openssl x509 -in $CERT_FILE -noout -serial)"
    }
    else {
        Write-Error "Certificate file not found: $CERT_FILE"
    }
}

# Function to create development certificate
function New-DevelopmentCertificate {
    Write-Header "Creating development certificate..."
    
    if (-not (Test-OpenSSL)) { exit 1 }
    New-CertificateDirectory
    New-OpenSSLConfig
    New-PrivateKey
    New-SelfSignedCertificate
    Test-Certificate
    Show-CertificateInfo
    
    Write-Status "Development certificate created successfully!"
    Write-Warning "This is a self-signed certificate for development only."
    Write-Warning "For production, use Let's Encrypt or commercial certificates."
}

# Function to create production certificate
function New-ProductionCertificate {
    Write-Header "Creating production certificate..."
    
    if (-not (Test-OpenSSL)) { exit 1 }
    New-CertificateDirectory
    New-OpenSSLConfig
    New-PrivateKey
    New-LetsEncryptCertificate
    
    Write-Status "Production certificate setup completed!"
    Write-Status "Next steps:"
    Write-Host "1. Use the CSR file with Let's Encrypt:"
    Write-Host "   certbot certonly --csr $CSR_FILE"
    Write-Host "2. Or submit the CSR to your CA"
    Write-Host "3. Place the received certificate in $CERT_FILE"
}

# Function to show usage
function Show-Usage {
    Write-Host "Usage: .\generate-certs.ps1 [OPTION]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  dev     Generate self-signed certificate for development"
    Write-Host "  prod    Generate CSR for production (Let's Encrypt)"
    Write-Host "  verify  Verify existing certificate"
    Write-Host "  info    Show certificate information"
    Write-Host "  help    Show this help message"
    Write-Host ""
    Write-Host "Environment variables:"
    Write-Host "  COUNTRY              Country code (default: US)"
    Write-Host "  STATE                State/Province (default: State)"
    Write-Host "  CITY                 City (default: City)"
    Write-Host "  ORGANIZATION         Organization name (default: Secure Fullstack App)"
    Write-Host "  COMMON_NAME          Common name (default: localhost)"
    Write-Host "  VALIDITY_DAYS        Certificate validity in days (default: 365)"
    Write-Host "  KEY_SIZE             RSA key size (default: 2048)"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\generate-certs.ps1 dev"
    Write-Host "  .\generate-certs.ps1 prod"
    Write-Host "  `$env:COMMON_NAME='example.com'; .\generate-certs.ps1 dev"
}

# Main script logic
switch ($Action) {
    "dev" {
        New-DevelopmentCertificate
    }
    "prod" {
        New-ProductionCertificate
    }
    "verify" {
        Test-Certificate
    }
    "info" {
        Show-CertificateInfo
    }
    "help" {
        Show-Usage
    }
    default {
        Show-Usage
    }
} 