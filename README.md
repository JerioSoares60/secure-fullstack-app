# 🔐 Secure Fullstack App

A military-grade end-to-end encryption (E2EE) web application with AES-256-GCM and ECC hybrid encryption. This system provides transparent encryption for all client-server communication, making it resistant to penetration testing and hacking techniques.

## 🚀 Features

- **Military-Grade Encryption**: AES-256-GCM with random IVs and authentication
- **ECC Key Exchange**: Elliptic Curve Cryptography for secure key establishment
- **Hybrid Encryption**: Combines symmetric and asymmetric encryption
- **Session Management**: Secure session handling with automatic key rotation
- **HMAC Signatures**: Message authentication and integrity verification
- **Plugin Architecture**: Transparent encryption layer without changing app logic
- **Auto Handshake**: Automatic public key exchange during connection
- **Production Ready**: Dockerized deployment with NGINX reverse proxy

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend│    │   FastAPI Backend│    │   NGINX Proxy   │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Crypto    │ │    │ │  Encryptor  │ │    │ │   SSL/TLS   │ │
│ │   Client    │ │    │ │  Middleware │ │    │ │   Reverse   │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ │    Proxy    │ │
│                 │    │                 │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │                 │
│ │   Axios     │ │    │ │   Session   │ │    │ ┌─────────────┐ │
│ │ Interceptor │ │    │ │  Manager    │ │    │ │   Security  │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ │   Headers   │ │
└─────────────────┘    └─────────────────┘    │ └─────────────┘ │
                                              └─────────────────┘
```

## 🔧 Technology Stack

### Backend
- **FastAPI**: Modern Python web framework
- **Cryptography**: Military-grade encryption libraries
- **Pydantic**: Data validation and serialization
- **Uvicorn**: ASGI server

### Frontend
- **React**: Modern JavaScript framework
- **Vite**: Fast build tool
- **Web Crypto API**: Browser-native cryptography
- **Axios**: HTTP client with interceptors

### Infrastructure
- **Docker**: Containerization
- **NGINX**: Reverse proxy and load balancer
- **Redis**: Session storage (optional)
- **PostgreSQL**: Database (optional)

## 📦 Installation

### Prerequisites
- Docker and Docker Compose
- Node.js 18+ (for development)
- Python 3.11+ (for development)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure-fullstack-app
   ```

2. **Set up environment variables**
   ```bash
   # Copy example files
   cp backend/env.example backend/.env
   cp frontend/env.example frontend/.env
   
   # Edit the files with your secure keys
   nano backend/.env
   nano frontend/.env
   ```

3. **Generate secure keys**
   ```bash
   # Generate a 32-character secret key for backend
   openssl rand -base64 32
   
   # Generate a legacy encryption key for frontend
   openssl rand -base64 32
   ```

4. **Start the application**
   ```bash
   docker-compose up -d
   ```

5. **Access the application**
   - Frontend: http://localhost
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

## 🔐 Security Features

### Encryption Layers

1. **ECC Key Exchange**
   - Client and server generate ECC key pairs
   - Public keys exchanged during handshake
   - Shared secret derived using ECDH

2. **AES-256-GCM Encryption**
   - 256-bit AES encryption in GCM mode
   - Random 12-byte IV for each encryption
   - 16-byte authentication tag
   - Authenticated encryption with associated data

3. **HMAC Signatures**
   - SHA-256 HMAC for message authentication
   - Prevents tampering and replay attacks
   - Signature verification on all messages

4. **Session Management**
   - 24-hour session expiration
   - Automatic session cleanup
   - Session key derivation using HKDF

### Security Headers

- **X-Frame-Options**: Prevent clickjacking
- **X-Content-Type-Options**: Prevent MIME sniffing
- **X-XSS-Protection**: XSS protection
- **Content-Security-Policy**: Resource loading restrictions
- **Referrer-Policy**: Control referrer information
- **Permissions-Policy**: Feature policy restrictions

## 🛠️ Development

### Backend Development

1. **Set up virtual environment**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Run development server**
   ```bash
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Frontend Development

1. **Install dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Run development server**
   ```bash
   npm run dev
   ```

### API Testing

```bash
# Test handshake
curl -X POST http://localhost:8000/api/v1/handshake \
  -H "Content-Type: application/json" \
  -d '{"client_public_key": "base64-key", "client_id": "test-client"}'

# Test secure data endpoint
curl -X POST http://localhost:8000/api/v1/secure/data \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"encrypted_data": {...}, "client_id": "test-client"}'
```

## 📊 API Endpoints

### Authentication
- `POST /api/v1/handshake` - Perform ECC key exchange
- `GET /api/v1/session/{session_id}` - Get session information
- `DELETE /api/v1/session/{session_id}` - Invalidate session

### Secure Data
- `POST /api/v1/secure/data` - Process encrypted data
- `POST /api/v1/secure/user` - Handle encrypted user data
- `POST /api/v1/secure/message` - Handle encrypted messages

### Utilities
- `GET /api/v1/health` - Health check
- `GET /health` - Root health check

## 🔒 Production Deployment

### Environment Variables

```bash
# Backend (.env)
APP_SECRET_KEY=your-super-secret-32-character-key-here
ENVIRONMENT=production
SSL_KEYFILE=/path/to/ssl/private.key
SSL_CERTFILE=/path/to/ssl/certificate.crt

# Frontend (.env)
VITE_API_BASE_URL=https://your-domain.com
VITE_ENCRYPTION_KEY=your-legacy-encryption-key-here
```

### SSL Certificate Generation

```bash
# Generate self-signed certificate for development
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/private.key \
  -out certs/certificate.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# For production, use Let's Encrypt or commercial certificates
```

### Docker Deployment

```bash
# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f

# Scale services
docker-compose up -d --scale backend=3

# Update application
docker-compose pull
docker-compose up -d
```

## 🧪 Testing

### Security Testing

```bash
# Test encryption strength
python -c "
from app.encryptor import encrypt_data, decrypt_data
import json
data = {'test': 'sensitive data'}
encrypted = encrypt_data(data, 'test-session')
decrypted = decrypt_data(encrypted)
print('Encryption test:', data == decrypted)
"

# Test session management
curl -X POST http://localhost:8000/api/v1/handshake \
  -H "Content-Type: application/json" \
  -d '{"client_public_key": "test", "client_id": "test"}'
```

### Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test API performance
ab -n 1000 -c 10 http://localhost:8000/api/v1/health
```

## 📈 Monitoring

### Health Checks
- Backend: `http://localhost:8000/health`
- Frontend: `http://localhost/health`
- NGINX: `http://localhost/health`

### Logs
```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs backend
docker-compose logs frontend
docker-compose logs nginx

# Follow logs in real-time
docker-compose logs -f
```

## 🔧 Configuration

### NGINX Configuration
The NGINX configuration includes:
- Rate limiting (10 req/s for API, 1 req/s for login)
- Security headers
- Gzip compression
- SSL/TLS termination
- Reverse proxy to backend

### Docker Configuration
- Multi-stage builds for security
- Non-root users
- Resource limits
- Health checks
- Volume mounts for persistence

## 🚨 Security Considerations

### Key Management
- Store secrets in environment variables
- Use secure key generation
- Rotate keys regularly
- Never commit secrets to version control

### Network Security
- Use HTTPS in production
- Implement proper firewall rules
- Monitor network traffic
- Use VPN for admin access

### Application Security
- Keep dependencies updated
- Implement rate limiting
- Use secure session management
- Monitor for suspicious activity

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API docs at `/docs`

## 🔄 Changelog

### v1.0.0
- Initial release with military-grade E2EE
- AES-256-GCM + ECC hybrid encryption
- Automatic handshake and session management
- Dockerized deployment
- Comprehensive security features

---

**⚠️ Security Notice**: This application implements military-grade encryption. Ensure you understand the security implications and use it responsibly. Always keep your encryption keys secure and never share them. 