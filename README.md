# Monarchs Chat System - Production Edition

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-green)
![Erlang](https://img.shields.io/badge/erlang-%3E%3D26.0-yellow)
![License](https://img.shields.io/badge/license-ISC-lightgrey)

**A production-ready real-time chat system built with Erlang/OTP and Node.js**

[Features](#features) • [Architecture](#architecture) • [Quick Start](#quick-start) • [Configuration](#configuration) • [Deployment](#deployment)

</div>

---

## 🎯 Features

### Backend (Erlang/OTP)
- ✅ **OTP Supervision Tree** with fault tolerance
- ✅ **Secure password hashing** with salt + SHA-512
- ✅ **JWT-like session tokens** with expiry
- ✅ **Rate limiting** to prevent brute force attacks
- ✅ **ETS tables** for in-memory data storage
- ✅ **Connection pooling** via supervisor limits
- ✅ **Structured logging** with audit trail

### WebSocket Relay (Node.js)
- ✅ **WebSocket Server** with connection management
- ✅ **Security headers** via Helmet
- ✅ **CORS support** for cross-origin requests
- ✅ **Rate limiting** per IP and per connection
- ✅ **Structured JSON logging** with Pino
- ✅ **Health check endpoint** (`/health`)
- ✅ **Prometheus metrics** (`/metrics`)
- ✅ **Graceful shutdown** handling

### Deployment
- ✅ **Docker support** for both services
- ✅ **Docker Compose** for local development
- ✅ **GitHub Actions CI/CD** pipeline
- ✅ **Security scanning** with Trivy and Snyk

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              index.html (Web UI)                             │ │
│  │  • Telegram/WhatsApp-style interface                        │ │
│  │  • Dark theme with responsive design                        │ │
│  │  • WebSocket connection management                          │ │
│  └────────────────────────┬────────────────────────────────────┘ │
└─────────────────────────────┼──────────────────────────────────────┘
                              │ WebSocket (ws://)
┌─────────────────────────────┴──────────────────────────────────────┐
│                     RELAY LAYER (Node.js)                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              server.js (WebSocket → TCP relay)               │   │
│  │  • Connection management & rate limiting                     │   │
│  │  • Token verification & refresh                              │   │
│  │  • Health & metrics endpoints                               │   │
│  │  • Structured JSON logging                                  │   │
│  └────────────────────────┬────────────────────────────────────┘   │
└─────────────────────────────┼──────────────────────────────────────┘
                              │ TCP (localhost:5678)
┌─────────────────────────────┴──────────────────────────────────────┐
│                   CORE LAYER (Erlang/OTP)                         │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                        OTP Supervision Tree                    │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │   monarchs_app (Application)                            │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  │                              ▲                                │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │   monarchs_sup (Root Supervisor)                        │  │  │
│  │  │   ├── monarchs_config (Config Server)                   │  │  │
│  │  │   ├── monarchs_server (Main gen_server)                 │  │  │
│  │  │   ├── monarchs_user_sup (User Supervisor)              │  │  │
│  │  │   ├── monarchs_room_sup (Room Supervisor)              │  │  │
│  │  │   └── monarchs_connection_sup (Connection Supervisor)  │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  │                              │                                │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │   ETS Tables                                            │  │  │
│  │  │   • monarchs_users (User registry)                     │  │  │
│  │  │   • monarchs_rooms (Room registry)                     │  │  │
│  │  │   • monarchs_messages (Message history)                │  │  │
│  │  │   • monarchs_sessions (Session store)                   │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** >= 18.0.0
- **Erlang/OTP** >= 26
- **Docker** & **Docker Compose** (optional)

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/monarchs.git
cd monarchs

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
nano .env

# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f

# Verify health
curl http://localhost:8080/health
```

### Option 2: Manual Setup

```bash
# Clone the repository
git clone https://github.com/your-org/monarchs.git
cd monarchs

# Install Node.js dependencies
npm install

# Start Erlang backend (in one terminal)
erl -pa src -s monarchs_app -noshell

# Start Node.js relay (in another terminal)
npm start

# Open browser
# Navigate to http://localhost:8080
```

---

## 📁 Project Structure

```
Monarchs/
├── src/                        # Erlang/OTP Backend
│   ├── monarchs_app.erl        # Application callback
│   ├── monarchs_sup.erl        # Root supervisor
│   ├── monarchs_config.erl     # Configuration server
│   ├── monarchs_server.erl     # Main gen_server
│   ├── monarchs_user_sup.erl   # User process supervisor
│   ├── monarchs_room_sup.erl   # Room process supervisor
│   ├── monarchs_connection_sup.erl  # Connection supervisor
│   └── monarchs_connection.erl # Connection handler
├── tests/                      # Test suite
│   └── server.test.js          # Node.js tests
├── server.js                   # WebSocket relay server
├── config.yaml                 # Application configuration
├── package.json                # Node.js dependencies
├── Dockerfile.erlang           # Erlang backend image
├── Dockerfile.node             # Node.js relay image
├── docker-compose.yml          # Container orchestration
├── .env.example                # Environment template
└── README.md                   # This file
```

---

## ⚙️ Configuration

### config.yaml

All settings can be configured in `config.yaml`:

```yaml
# Application Settings
app:
  name: "monarchs"
  version: "2.0.0"
  environment: "production"

# Backend Settings
backend:
  host: "0.0.0.0"
  port: 5678
  max_connections: 10000

# Security Settings
security:
  bcrypt_cost: 12
  token_expiry: 3600
  refresh_token_expiry: 86400
  rate_limit:
    max_attempts: 5
    window_ms: 60000
  password:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_numbers: true

# WebSocket Relay Settings
relay:
  host: "0.0.0.0"
  port: 8080
  path: "/ws"
  heartbeat_interval: 30000
  max_payload_size: 65536

# Logging
logging:
  level: "info"
  format: "json"
  audit:
    enabled: true

# Monitoring
monitoring:
  health:
    enabled: true
    path: "/health"
  metrics:
    enabled: true
    path: "/metrics"
```

### Environment Variables

Override configuration with environment variables:

| Variable | Description |
|----------|-------------|
| `MONARCHS_TOKEN_SECRET` | Secret for JWT tokens (generate with `openssl rand -hex 64`) |
| `MONARCHS_PORT` | Erlang backend port (default: 5678) |
| `MONARCHS_RELAY_PORT` | WebSocket relay port (default: 8080) |
| `MONARCHS_LOG_LEVEL` | Logging level (debug, info, warn, error) |
| `NODE_ENV` | Environment (development, production) |
| `ERLANG_HOST` | Erlang backend hostname |
| `ERLANG_PORT` | Erlang backend port |

---

## 📡 API Reference

### WebSocket Messages

#### Authentication

**Register:**
```json
{"type": "register", "username": "user", "password": "pass"}
```

**Login:**
```json
{"type": "login", "username": "user", "password": "pass"}
```

**Response:**
```json
{
  "type": "success",
  "content": "Login successful!",
  "token": "eyJhbG...",
  "expiresIn": 3600000
}
```

#### Room Management

**Create Room:**
```json
{"type": "create_room", "room_name": "general"}
```

**Join Room:**
```json
{"type": "join_room", "room_name": "general"}
```

**Leave Room:**
```json
{"type": "leave"}
```

#### Messaging

**Send Message:**
```json
{"type": "message", "content": "Hello everyone!"}
```

**Private Message:**
```json
{"type": "private", "to_user": "username", "content": "Hello!"}
```

**Get Rooms:**
```json
{"type": "get_rooms"}
```

**Get Users:**
```json
{"type": "get_users"}
```

### HTTP Endpoints

#### Health Check
```
GET /health
```
Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 3600,
  "memory": {...},
  "erlang": {"connected": true, "lastPing": 1234567890},
  "checks": {"erlang": "ok"}
}
```

#### Metrics (Prometheus)
```
GET /metrics
```
Returns Prometheus-compatible metrics format.

#### Server Info
```
GET /info
```
Returns service version and uptime.

---

## 🔐 Security Features

### Authentication
- **Password Hashing**: SHA-512 with unique salt per user
- **Session Tokens**: JWT-like tokens with expiry
- **Token Refresh**: Automatic token refresh capability

### Rate Limiting
- **Login Attempts**: 5 attempts per minute per IP
- **Messages**: 30 messages per second per connection
- **Connections**: 10 connections per IP

### Transport Security
- **HTTPS**: Enable with reverse proxy (nginx, Traefik)
- **WSS**: WebSocket over TLS
- **Helmet**: Security headers

### Audit Logging
- Login attempts (success/failure)
- Registration events
- Session creation/destruction
- Security violations

---

## 🧪 Testing

### Run Tests

```bash
# Install dependencies
npm install

# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Watch mode
npm run test:watch
```

### Linting

```bash
# Check code style
npm run lint

# Auto-fix issues
npm run lint:fix
```

### Security Audit

```bash
# Check for vulnerabilities
npm run security:audit
```

---

## 🚢 Deployment

### Docker Production

```bash
# Build images
docker-compose build

# Deploy
docker-compose -f docker-compose.yml up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Kubernetes

See [k8s/](./k8s/) directory for Kubernetes manifests.

### Manual Production

```bash
# Build Erlang backend
cd /path/to/monarchs
erlc -o src src/*.erl
erl -pa src -s monarchs_app -detached

# Build Node.js relay
npm ci --production
npm start
```

---

## 📊 Monitoring

### Health Checks

```bash
# Check relay health
curl http://localhost:8080/health

# Check Prometheus metrics
curl http://localhost:8080/metrics
```

### Logs

```bash
# View relay logs
docker-compose logs -f node-relay

# View backend logs
docker-compose logs -f erlang-backend
```

---

## 🔧 Maintenance

### Database Migrations

```bash
# (Future) Run migrations
npm run migrate
```

### Rolling Restart

```bash
# Restart without downtime
docker-compose restart node-relay
```

### Backup

```bash
# Backup session data
docker-compose exec redis redis-cli BGSAVE
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Erlang/OTP](https://www.erlang.org/) for the robust BEAM VM
- [Node.js](https://nodejs.org/) for the efficient JavaScript runtime
- [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket) for real-time communication

# Monarchs
