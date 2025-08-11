# Quick Start Script for Secure Fullstack App
# This script helps you get the application running quickly

param(
    [switch]$SkipCertificates,
    [switch]$SkipDocker,
    [switch]$Help
)

# Colors for output
$Green = "Green"
$Yellow = "Yellow"
$Red = "Red"
$Blue = "Blue"

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

function Write-Header {
    param([string]$Message)
    Write-Host "================================`n  $Message`n================================" -ForegroundColor $Blue
}

function Show-Help {
    Write-Host "Usage: .\quick-start.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -SkipCertificates    Skip SSL certificate generation"
    Write-Host "  -SkipDocker          Skip Docker setup"
    Write-Host "  -Help                Show this help message"
    Write-Host ""
    Write-Host "This script will:"
    Write-Host "1. Check prerequisites"
    Write-Host "2. Generate SSL certificates (unless skipped)"
    Write-Host "3. Set up environment files"
    Write-Host "4. Start the application with Docker"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\quick-start.ps1"
    Write-Host "  .\quick-start.ps1 -SkipCertificates"
    Write-Host "  .\quick-start.ps1 -SkipDocker"
}

if ($Help) {
    Show-Help
    exit 0
}

# Main script
Write-Header "Secure Fullstack App - Quick Start"

# Step 1: Check prerequisites
Write-Status "Checking prerequisites..."

# Check Docker
try {
    $dockerVersion = docker --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Docker found: $dockerVersion"
    }
    else {
        Write-Error "Docker is not installed or not running"
        Write-Warning "Please install Docker Desktop and ensure it's running"
        exit 1
    }
}
catch {
    Write-Error "Docker is not installed"
    Write-Warning "Please install Docker Desktop from https://www.docker.com/products/docker-desktop"
    exit 1
}

# Check Docker Compose
try {
    $composeVersion = docker-compose --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Docker Compose found: $composeVersion"
    }
    else {
        Write-Error "Docker Compose is not available"
        exit 1
    }
}
catch {
    Write-Error "Docker Compose is not available"
    exit 1
}

# Step 2: Generate SSL certificates (if not skipped)
if (-not $SkipCertificates) {
    Write-Status "Generating SSL certificates..."
    
    # Check if OpenSSL is available
    try {
        $opensslVersion = openssl version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "OpenSSL found: $opensslVersion"
            
            # Generate development certificate
            .\generate-certs.ps1 dev
        }
        else {
            Write-Warning "OpenSSL not found, skipping certificate generation"
            Write-Warning "You can generate certificates later with: .\generate-certs.ps1 dev"
        }
    }
    catch {
        Write-Warning "OpenSSL not found, skipping certificate generation"
        Write-Warning "You can generate certificates later with: .\generate-certs.ps1 dev"
    }
}
else {
    Write-Status "Skipping SSL certificate generation"
}

# Step 3: Set up environment files
Write-Status "Setting up environment files..."

# Backend environment
if (-not (Test-Path "backend\.env")) {
    if (Test-Path "backend\env.example") {
        Copy-Item "backend\env.example" "backend\.env"
        Write-Status "Created backend\.env from template"
        
        # Generate a secure key for backend
        $secureKey = -join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        (Get-Content "backend\.env") -replace "your-super-secret-32-character-key-here", $secureKey | Set-Content "backend\.env"
        Write-Status "Generated secure APP_SECRET_KEY for backend"
    }
    else {
        Write-Warning "backend\env.example not found, creating basic .env"
        @"
# Backend Environment Configuration
APP_SECRET_KEY=$(-join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_}))
ENVIRONMENT=development
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO
"@ | Out-File -FilePath "backend\.env" -Encoding UTF8
    }
}
else {
    Write-Status "backend\.env already exists"
}

# Frontend environment
if (-not (Test-Path "frontend\.env")) {
    if (Test-Path "frontend\env.example") {
        Copy-Item "frontend\env.example" "frontend\.env"
        Write-Status "Created frontend\.env from template"
        
        # Generate a secure key for frontend
        $legacyKey = -join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        (Get-Content "frontend\.env") -replace "your-legacy-encryption-key-here", $legacyKey | Set-Content "frontend\.env"
        Write-Status "Generated secure VITE_ENCRYPTION_KEY for frontend"
    }
    else {
        Write-Warning "frontend\env.example not found, creating basic .env"
        @"
# Frontend Environment Configuration
VITE_API_BASE_URL=http://localhost:8000
VITE_ENCRYPTION_KEY=$(-join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_}))
VITE_APP_NAME=Secure Fullstack App
VITE_APP_VERSION=1.0.0
VITE_ENABLE_HTTPS=true
VITE_STRICT_CSP=true
VITE_ENABLE_DEBUG_MODE=false
VITE_ENABLE_CRYPTO_LOGGING=false
"@ | Out-File -FilePath "frontend\.env" -Encoding UTF8
    }
}
else {
    Write-Status "frontend\.env already exists"
}

# Step 4: Start the application (if not skipped)
if (-not $SkipDocker) {
    Write-Status "Starting the application with Docker..."
    
    # Build and start services
    Write-Status "Building and starting services..."
    docker-compose up -d --build
    
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Application started successfully!"
        Write-Host ""
        Write-Host "🌐 Access your application:"
        Write-Host "   Frontend: http://localhost"
        Write-Host "   Backend API: http://localhost:8000"
        Write-Host "   API Documentation: http://localhost:8000/docs"
        Write-Host ""
        Write-Host "📊 Monitor the application:"
        Write-Host "   View logs: docker-compose logs -f"
        Write-Host "   Stop services: docker-compose down"
        Write-Host "   Restart services: docker-compose restart"
        Write-Host ""
        Write-Host "🔐 Security features:"
        Write-Host "   - Military-grade AES-256-GCM encryption"
        Write-Host "   - ECC key exchange for secure handshake"
        Write-Host "   - HMAC signatures for message integrity"
        Write-Host "   - Automatic session management"
        Write-Host ""
        Write-Host "✅ Your secure fullstack application is ready!"
    }
    else {
        Write-Error "Failed to start the application"
        Write-Host ""
        Write-Host "Troubleshooting:"
        Write-Host "1. Check if Docker is running"
        Write-Host "2. Check the logs: docker-compose logs"
        Write-Host "3. Try rebuilding: docker-compose up -d --build"
        Write-Host "4. Check port availability (80, 8000)"
        exit 1
    }
}
else {
    Write-Status "Skipping Docker startup"
    Write-Host ""
    Write-Host "To start the application manually:"
    Write-Host "   docker-compose up -d --build"
    Write-Host ""
    Write-Host "To run in development mode:"
    Write-Host "   Backend: cd backend && python -m uvicorn app.main:app --reload"
    Write-Host "   Frontend: cd frontend && npm run dev"
}

Write-Header "Quick Start Complete!" 