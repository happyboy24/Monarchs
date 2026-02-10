/**
 * Monarchs Chat System - Production WebSocket Relay Server
 * 
 * Production-ready Node.js WebSocket server with:
 * - Configuration management via config.yaml
 * - Security headers with Helmet
 * - CORS support
 * - Structured JSON logging
 * - Health and metrics endpoints
 * - JWT authentication
 * - Rate limiting
 * - Graceful shutdown
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const WebSocket = require('ws');
const url = require('url');

// Security middleware
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// Logging
const pino = require('pino');

// Configuration
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(__dirname, 'config.yaml');
const env = process.env.NODE_ENV || 'production';

// ===================================================================
// Configuration Management
// ===================================================================

class Config {
    constructor() {
        this.config = this.loadConfig();
        this.validate();
    }

    loadConfig() {
        try {
            const configFile = fs.readFileSync(CONFIG_PATH, 'utf8');
            // Simple YAML parser for our config format
            const config = this.parseYAML(configFile);
            
            // Apply environment variable overrides
            return this.applyEnvOverrides(config);
        } catch (error) {
            console.error('Failed to load config.yaml:', error.message);
            return this.getDefaultConfig();
        }
    }

    parseYAML(yaml) {
        const result = {};
        const lines = yaml.split('\n');
        let currentSection = null;
        let currentSubsection = null;
        
        for (const line of lines) {
            const trimmed = line.trim();
            
            // Skip comments and empty lines
            if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('---')) continue;
            
            // Check for section headers
            if (trimmed.endsWith(':')) {
                const sectionName = trimmed.slice(0, -1).trim();
                
                if (trimmed.startsWith('  ')) {
                    // Subsection
                    currentSubsection = sectionName;
                    if (!result[currentSection]) result[currentSection] = {};
                    result[currentSection][currentSubsection] = {};
                } else {
                    // Main section
                    currentSection = sectionName;
                    currentSubsection = null;
                    if (!result[currentSection]) result[currentSection] = {};
                }
            } else if (trimmed.includes(':')) {
                const [key, ...valueParts] = trimmed.split(':');
                const value = valueParts.join(':').trim();
                
                if (value === '' || value === 'true' || value === 'false') {
                    // Boolean or empty
                    const parsedValue = value === 'true' ? true : value === 'false' ? false : undefined;
                    if (parsedValue !== undefined) {
                        if (currentSubsection) {
                            result[currentSection][currentSubsection][key.trim()] = parsedValue;
                        } else if (currentSection) {
                            result[currentSection][key.trim()] = parsedValue;
                        }
                    }
                } else if (!isNaN(value)) {
                    // Number
                    const num = parseFloat(value);
                    if (currentSubsection) {
                        result[currentSection][currentSubsection][key.trim()] = num;
                    } else if (currentSection) {
                        result[currentSection][key.trim()] = num;
                    }
                } else {
                    // String
                    if (currentSubsection) {
                        result[currentSection][currentSubsection][key.trim()] = value.replace(/"/g, '');
                    } else if (currentSection) {
                        result[currentSection][key.trim()] = value.replace(/"/g, '');
                    }
                }
            }
        }
        
        return result;
    }

    applyEnvOverrides(config) {
        // Environment variable overrides
        if (process.env.MONARCHS_PORT) {
            config.relay = config.relay || {};
            config.relay.port = parseInt(process.env.MONARCHS_PORT, 10);
        }
        if (process.env.MONARCHS_RELAY_PORT) {
            config.relay = config.relay || {};
            config.relay.port = parseInt(process.env.MONARCHS_RELAY_PORT, 10);
        }
        if (process.env.MONARCHS_LOG_LEVEL) {
            config.logging = config.logging || {};
            config.logging.level = process.env.MONARCHS_LOG_LEVEL;
        }
        if (process.env.MONARCHS_TOKEN_SECRET) {
            config.security = config.security || {};
            config.security.token_secret = process.env.MONARCHS_TOKEN_SECRET;
        }
        if (process.env.MONARCHS_DB_URL) {
            config.persistence = config.persistence || {};
            config.persistence.database = config.persistence.database || {};
            config.persistence.database.url = process.env.MONARCHS_DB_URL;
        }
        if (process.env.MONARCHS_REDIS_URL) {
            config.persistence = config.persistence || {};
            config.persistence.redis = config.persistence.redis || {};
            config.persistence.redis.url = process.env.MONARCHS_REDIS_URL;
        }
        
        return config;
    }

    getDefaultConfig() {
        return {
            app: {
                name: 'monarchs',
                version: '2.0.0',
                environment: env
            },
            relay: {
                host: '0.0.0.0',
                port: parseInt(process.env.WS_PORT || '8080', 10),
                path: '/ws',
                heartbeat_interval: 30000,
                connection_timeout: 60000,
                max_payload_size: 65536
            },
            security: {
                token_secret: process.env.TOKEN_SECRET || crypto.randomBytes(64).toString('hex'),
                token_expiry: 3600000,
                bcrypt_cost: 12
            },
            logging: {
                level: process.env.LOG_LEVEL || 'info',
                format: 'json'
            },
            cors: {
                enabled: true,
                origins: ['*'],
                credentials: true
            },
            monitoring: {
                health: { enabled: true, path: '/health' },
                metrics: { enabled: true, path: '/metrics' }
            }
        };
    }

    validate() {
        // Validate critical configuration
        if (!this.config.relay || !this.config.relay.port) {
            throw new Error('Relay port must be configured');
        }
        if (!this.config.security || !this.config.security.token_secret) {
            throw new Error('Token secret must be configured');
        }
    }

    get(key, defaultValue = undefined) {
        const keys = key.split('.');
        let value = this.config;
        
        for (const k of keys) {
            if (value === undefined || value === null) return defaultValue;
            value = value[k];
        }
        
        return value !== undefined ? value : defaultValue;
    }
}

const config = new Config();

// ===================================================================
// Structured JSON Logging
// ===================================================================

const logger = pino({
    level: config.get('logging.level', 'info'),
    base: {
        service: 'monarchs-relay',
        version: '2.0.0',
        environment: config.get('app.environment', 'production')
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
        level: (label) => {
            return { level: label.toUpperCase() };
        }
    },
    serializers: pino.stdSerializers,
    ...(config.get('logging.format') === 'json' ? {} : { transport: { target: 'pino-pretty' } })
});

// ===================================================================
// HTTP Server Setup
// ===================================================================

const server = http.createServer((req, res) => {
    const startTime = Date.now();
    
    // Structured request logging
    const requestLogger = logger.child({
        request_id: crypto.randomUUID(),
        method: req.method,
        url: req.url,
        ip: req.ip
    });
    
    req.on('end', () => {
        requestLogger.info({
            status_code: res.statusCode,
            response_time: Date.now() - startTime
        });
    });
    
    handleRequest(req, res);
});

// ===================================================================
// Request Handlers
// ===================================================================

function handleRequest(req, res) {
    const pathname = url.parse(req.url).pathname;
    
    // CORS preflight
    if (req.method === 'OPTIONS') {
        return handleCORS(req, res);
    }
    
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    // Health check endpoint
    if (pathname === '/health' && config.get('monitoring.health.enabled', true)) {
        return handleHealth(res);
    }
    
    // Metrics endpoint (Prometheus format)
    if (pathname === '/metrics' && config.get('monitoring.metrics.enabled', true)) {
        return handleMetrics(res);
    }
    
    // Ready check
    if (pathname === '/ready') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ready: true, erlangConnected: erlangSocket && connected }));
        return;
    }
    
    // Root info
    if (pathname === '/' || pathname === '/info') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            service: 'monarchs-relay',
            version: '2.0.0',
            uptime: process.uptime(),
            timestamp: new Date().toISOString()
        }));
        return;
    }
    
    // 404 for unknown routes
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
}

function handleCORS(req, res) {
    const origins = config.get('cors.origins', ['*']);
    const origin = req.headers.origin || '*';
    
    if (origins.includes('*') || origins.includes(origin)) {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '86400'
        });
    }
    res.end();
}

function handleHealth(res) {
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        erlang: {
            connected: connected,
            lastPing: lastPingTime
        },
        checks: {
            erlang: connected ? 'ok' : 'disconnected'
        }
    };
    
    const statusCode = connected ? 200 : 503;
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(health, null, 2));
}

function handleMetrics(res) {
    // Prometheus-compatible metrics format
    const metrics = [
        '# HELP monarchs_relay_info Information about the relay service',
        '# TYPE monarchs_relay_info gauge',
        `monarchs_relay_info{version="2.0.0",environment="${config.get('app.environment', 'production')}"} 1`,
        '',
        '# HELP monarchs_relay_uptime_seconds_total Uptime in seconds',
        '# TYPE monarchs_relay_uptime_seconds_total counter',
        `monarchs_relay_uptime_seconds_total ${process.uptime()}`,
        '',
        '# HELP monarchs_relay_memory_bytes Memory usage in bytes',
        '# TYPE monarchs_relay_memory_bytes gauge',
        `monarchs_relay_memory_bytes{type="heap"} ${process.memoryUsage().heapUsed}`,
        `monarchs_relay_memory_bytes{type="rss"} ${process.memoryUsage().rss}`,
        '',
        '# HELP monarchs_relay_websocket_connections_active Current active WebSocket connections',
        '# TYPE monarchs_relay_websocket_connections_active gauge',
        `monarchs_relay_websocket_connections_active ${wss ? wss.clients.size : 0}`,
        '',
        '# HELP monarchs_relay_erlang_connections Erlang connection status',
        '# TYPE monarchs_relay_erlang_connections gauge',
        `monarchs_relay_erlang_connections ${connected ? 1 : 0}`,
        '',
        '# HELP monarchs_relay_http_requests_total Total HTTP requests',
        '# TYPE monarchs_relay_http_requests_total counter',
        `monarchs_relay_http_requests_total ${requestCount}`,
        '',
        '# HELP monarchs_relay_websocket_messages_total Total WebSocket messages processed',
        '# TYPE monarchs_relay_websocket_messages_total counter',
        `monarchs_relay_websocket_messages_total ${messageCount}`
    ].join('\n');
    
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(metrics);
}

// ===================================================================
// WebSocket Server
// ===================================================================

const wss = new WebSocket.Server({
    server,
    path: config.get('relay.path', '/ws'),
    verifyClient: (info, callback) => {
        // Rate limit new connections
        const clientIp = info.req.socket.remoteAddress;
        const connectionCount = connectionTracker.get(clientIp) || 0;
        const maxConnections = config.get('relay.rate_limit.max_connections_per_ip', 10);
        
        if (connectionCount >= maxConnections) {
            logger.warn({ ip: clientIp, count: connectionCount }, 'Connection rate limit exceeded');
            callback(false, 429, 'Too Many Connections');
            return;
        }
        
        // Validate origin
        const origin = info.req.headers.origin;
        const allowedOrigins = config.get('cors.origins', ['*']);
        
        if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
            connectionTracker.set(clientIp, connectionCount + 1);
            callback(true);
        } else {
            logger.warn({ origin, ip: clientIp }, 'Rejected connection from unauthorized origin');
            callback(false, 403, 'Forbidden');
        }
    }
});

// ===================================================================
// Connection Tracking
// ===================================================================

const connectionTracker = new Map();
const connections = new Map();
const rateLimitMap = new Map();
const messageCount = 0;
const requestCount = 0;
let erlangSocket = null;
let connected = false;
let lastPingTime = null;

// ===================================================================
// Token Management
// ===================================================================

class TokenManager {
    constructor() {
        this.secret = config.get('security.token_secret');
        this.expiry = config.get('security.token_expiry', 3600000);
    }
    
    createToken(username) {
        const header = { alg: 'HS256', typ: 'JWT' };
        const payload = {
            sub: username,
            iat: Date.now(),
            exp: Date.now() + this.expiry,
            jti: crypto.randomUUID()
        };
        
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const signature = this.createSignature(`${encodedHeader}.${encodedPayload}`);
        
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }
    
    verifyToken(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                return { valid: false, error: 'Invalid token format' };
            }
            
            const [encodedHeader, encodedPayload, signature] = parts;
            const expectedSignature = this.createSignature(`${encodedHeader}.${encodedPayload}`);
            
            if (signature !== expectedSignature) {
                return { valid: false, error: 'Invalid signature' };
            }
            
            const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
            
            if (payload.exp < Date.now()) {
                return { valid: false, error: 'Token expired', expired: true };
            }
            
            return { valid: true, username: payload.sub, payload };
        } catch (error) {
            return { valid: false, error: 'Invalid token' };
        }
    }
    
    refreshToken(token) {
        const verification = this.verifyToken(token);
        if (!verification.valid) {
            return { error: verification.error };
        }
        
        return { token: this.createToken(verification.username) };
    }
    
    createSignature(data) {
        return crypto
            .createHmac('sha256', this.secret)
            .update(data)
            .digest('base64url');
    }
}

const tokenManager = new TokenManager();

// ===================================================================
// Rate Limiting
// ===================================================================

const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_MESSAGES_PER_WINDOW = 30;

function checkRateLimit(clientId) {
    const now = Date.now();
    const record = rateLimitMap.get(clientId);
    
    if (!record || now - record.windowStart > RATE_LIMIT_WINDOW) {
        rateLimitMap.set(clientId, { count: 1, windowStart: now });
        return { allowed: true, remaining: MAX_MESSAGES_PER_WINDOW - 1 };
    }
    
    if (record.count >= MAX_MESSAGES_PER_WINDOW) {
        const retryAfter = record.windowStart + RATE_LIMIT_WINDOW - now;
        return { allowed: false, retryAfter };
    }
    
    record.count++;
    rateLimitMap.set(clientId, record);
    return { allowed: true, remaining: MAX_MESSAGES_PER_WINDOW - record.count };
}

// Clean up old rate limit entries
setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitMap.entries()) {
        if (now - record.windowStart > RATE_LIMIT_WINDOW) {
            rateLimitMap.delete(key);
        }
    }
}, RATE_LIMIT_WINDOW);

// ===================================================================
// Erlang Connection
// ===================================================================

function connectToErlang() {
    const ERLANG_HOST = process.env.ERLANG_HOST || 'localhost';
    const ERLANG_PORT = parseInt(process.env.ERLANG_PORT || '5678', 10);
    
    const net = require('net');
    erlangSocket = new net.Socket();
    
    erlangSocket.connect(ERLANG_PORT, ERLANG_HOST, () => {
        connected = true;
        logger.info({ host: ERLANG_HOST, port: ERLANG_PORT }, 'Connected to Erlang server');
        
        // Send ping every 30 seconds
        setInterval(() => {
            if (erlangSocket && !erlangSocket.destroyed) {
                erlangSocket.write('/ping\n');
                lastPingTime = Date.now();
            }
        }, 30000);
    });
    
    erlangSocket.on('error', (err) => {
        connected = false;
        logger.error({ error: err.message }, 'Erlang connection error');
        
        // Reconnect after 5 seconds
        setTimeout(connectToErlang, 5000);
    });
    
    erlangSocket.on('close', () => {
        connected = false;
        logger.warn('Erlang connection closed');
    });
    
    erlangSocket.on('data', (data) => {
        const messages = parseResponse(data.toString());
        messages.forEach(msg => {
            logger.debug({ type: msg.type }, 'Received message from Erlang');
        });
    });
}

// ===================================================================
// WebSocket Message Handling
// ===================================================================

wss.on('connection', (ws, req) => {
    const clientId = req.socket.remoteAddress;
    const connectionId = crypto.randomUUID();
    
    logger.info({ clientId, connectionId }, 'New WebSocket connection');
    
    let username = null;
    let token = null;
    let currentRoom = null;
    let isAuthenticated = false;
    let lastActivity = Date.now();
    
    // Store connection
    connections.set(connectionId, {
        ws,
        clientId,
        username,
        connectedAt: Date.now()
    });
    
    // Connection timeout
    const timeout = setTimeout(() => {
        if (!isAuthenticated) {
            ws.close(1008, 'Authentication required');
        }
    }, config.get('relay.connection_timeout', 60000));
    
    ws.on('message', async (message) => {
        lastActivity = Date.now();
        
        // Rate limit check
        const rateLimit = checkRateLimit(`msg:${clientId}`);
        if (!rateLimit.allowed) {
            ws.send(JSON.stringify({
                type: 'error',
                content: 'Rate limit exceeded. Please slow down.',
                retryAfter: rateLimit.retryAfter
            }));
            return;
        }
        
        try {
            const data = JSON.parse(message.toString());
            logger.debug({ type: data.type, clientId }, 'Received WebSocket message');
            
            // Handle different message types
            await handleMessage(ws, connectionId, data, {
                username, token, currentRoom, isAuthenticated,
                setAuth: (u, t, auth) => { username = u; token = t; isAuthenticated = auth; },
                setRoom: (r) => { currentRoom = r; },
                erlangSocket
            });
        } catch (error) {
            logger.error({ error: error.message, clientId }, 'Error processing message');
            ws.send(JSON.stringify({
                type: 'error',
                content: 'Invalid request format'
            }));
        }
    });
    
    ws.on('close', () => {
        clearTimeout(timeout);
        connectionTracker.set(clientId, Math.max(0, (connectionTracker.get(clientId) || 1) - 1));
        connections.delete(connectionId);
        
        if (token) {
            erlangSocket?.write(`/logout\n`);
        }
        
        logger.info({ clientId, connectionId }, 'WebSocket connection closed');
    });
    
    ws.on('error', (error) => {
        logger.error({ error: error.message, clientId }, 'WebSocket error');
    });
});

// ===================================================================
// Message Handler
// ===================================================================

async function handleMessage(ws, connectionId, data, state) {
    const { username, token, currentRoom, isAuthenticated, setAuth, setRoom, erlangSocket } = state;
    
    switch (data.type) {
        case 'register':
            const registerResult = await sendToErlang(`/register ${data.username} ${data.password}`);
            setAuth(data.username, null, false);
            ws.send(JSON.stringify({ type: 'success', content: 'Registration successful! Please login.' }));
            break;
            
        case 'login':
            const loginResult = await sendToErlang(`/login ${data.username} ${data.password}`);
            
            if (loginResult.includes('Login successful')) {
                const newToken = tokenManager.createToken(data.username);
                setAuth(data.username, newToken, true);
                ws.send(JSON.stringify({
                    type: 'success',
                    content: 'Login successful!',
                    token: newToken,
                    expiresIn: config.get('security.token_expiry', 3600000)
                }));
            } else {
                ws.send(JSON.stringify({
                    type: 'error',
                    content: 'Invalid username or password'
                }));
            }
            break;
            
        case 'create_room':
            if (!isAuthenticated) {
                ws.send(JSON.stringify({ type: 'error', content: 'Authentication required' }));
                return;
            }
            const createResult = await sendToErlang(`/create ${data.room_name}`);
            ws.send(JSON.stringify({ type: 'success', content: 'Room created!' }));
            break;
            
        case 'join_room':
            if (!isAuthenticated) {
                ws.send(JSON.stringify({ type: 'error', content: 'Authentication required' }));
                return;
            }
            if (currentRoom) {
                await sendToErlang(`/leave`);
            }
            setRoom(data.room_name);
            const joinResult = await sendToErlang(`/join ${data.room_name}`);
            ws.send(JSON.stringify({ type: 'success', content: `Joined ${data.room_name}` }));
            break;
            
        case 'message':
            if (!isAuthenticated) {
                ws.send(JSON.stringify({ type: 'error', content: 'Authentication required' }));
                return;
            }
            if (!currentRoom) {
                ws.send(JSON.stringify({ type: 'error', content: 'Join a room first' }));
                return;
            }
            await sendToErlang(`${data.content}`);
            break;
            
        case 'private':
            if (!isAuthenticated) {
                ws.send(JSON.stringify({ type: 'error', content: 'Authentication required' }));
                return;
            }
            await sendToErlang(`/msg ${data.to_user} ${data.content}`);
            ws.send(JSON.stringify({ type: 'success', content: 'Private message sent' }));
            break;
            
        case 'get_rooms':
            if (!isAuthenticated) {
                ws.send(JSON.stringify({ type: 'error', content: 'Authentication required' }));
                return;
            }
            const rooms = await sendToErlang(`/rooms`);
            ws.send(JSON.stringify({ type: 'rooms', rooms: parseRoomsList(rooms) }));
            break;
            
        case 'get_users':
            if (!isAuthenticated) {
                ws.send(JSON.stringify({ type: 'error', content: 'Authentication required' }));
                return;
            }
            const users = await sendToErlang(`/users`);
            ws.send(JSON.stringify({ type: 'users', users: parseUsersList(users) }));
            break;
            
        case 'logout':
            if (token) {
                await sendToErlang(`/logout`);
            }
            setAuth(null, null, false);
            setRoom(null);
            ws.send(JSON.stringify({ type: 'system', content: 'Logged out' }));
            break;
            
        case 'refresh_token':
            if (!token) {
                ws.send(JSON.stringify({ type: 'error', content: 'Not authenticated' }));
                return;
            }
            const refreshed = tokenManager.refreshToken(token);
            if (refreshed.error) {
                ws.send(JSON.stringify({ type: 'error', content: refreshed.error }));
            } else {
                ws.send(JSON.stringify({
                    type: 'token_refresh',
                    token: refreshed.token,
                    expiresIn: config.get('security.token_expiry', 3600000)
                }));
            }
            break;
            
        case 'ping':
            ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
            break;
            
        default:
            ws.send(JSON.stringify({ type: 'error', content: 'Unknown message type' }));
    }
}

// ===================================================================
// Erlang Communication
// ===================================================================

function sendToErlang(message) {
    return new Promise((resolve) => {
        if (!erlangSocket || !connected) {
            resolve('Error: Not connected to Erlang server');
            return;
        }
        
        const responseHandler = (data) => {
            erlangSocket.removeListener('data', responseHandler);
            resolve(data.toString());
        };
        
        erlangSocket.once('data', responseHandler);
        erlangSocket.write(message + '\n');
        
        // Timeout after 5 seconds
        setTimeout(() => {
            erlangSocket.removeListener('data', responseHandler);
            resolve('Error: Request timeout');
        }, 5000);
    });
}

// ===================================================================
// Response Parsing
// ===================================================================

function parseResponse(data) {
    const lines = data.toString().split('\n');
    const messages = [];
    
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        
        // Check for various response types
        if (trimmed.includes('[PM from')) {
            const match = trimmed.match(/\[PM from (.+)\] (.+)/);
            if (match) {
                messages.push({
                    type: 'message',
                    sender: match[1],
                    content: match[2],
                    isPrivate: true
                });
                continue;
            }
        }
        
        if (trimmed.match(/^\[(.+)\] <(.+)> (.+)$/)) {
            const match = trimmed.match(/^\[(.+)\] <(.+)> (.+)$/);
            messages.push({
                type: 'message',
                room: match[1],
                sender: match[2],
                content: match[3]
            });
            continue;
        }
        
        if (trimmed.includes('Room created')) {
            messages.push({ type: 'success', content: 'Room created!' });
            continue;
        }
        
        if (trimmed.includes('Joined room')) {
            messages.push({ type: 'success', content: trimmed });
            continue;
        }
        
        if (trimmed.includes('Error:')) {
            messages.push({ type: 'error', content: trimmed.replace('Error: ', '') });
            continue;
        }
    }
    
    return messages;
}

function parseRoomsList(data) {
    const rooms = [];
    const lines = data.split('\n');
    for (const line of lines) {
        const room = line.replace(/^  - /, '').trim();
        if (room) rooms.push(room);
    }
    return rooms;
}

function parseUsersList(data) {
    const users = [];
    const match = data.match(/Registered users: \[(.*)\]/);
    if (match) {
        const userList = match[1].split(', ');
        for (const user of userList) {
            const cleanUser = user.replace(/'/g, '').trim();
            if (cleanUser) users.push(cleanUser);
        }
    }
    return users;
}

// ===================================================================
// Graceful Shutdown
// ===================================================================

async function shutdown(signal) {
    logger.info({ signal }, 'Received shutdown signal');
    
    // Close all WebSocket connections
    wss.clients.forEach((client) => {
        client.close(1001, 'Server shutting down');
    });
    
    // Close Erlang connection
    if (erlangSocket) {
        erlangSocket.end();
    }
    
    // Close HTTP server
    server.close(() => {
        logger.info('Server shut down gracefully');
        process.exit(0);
    });
    
    // Force exit after 30 seconds
    setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
    }, 30000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.fatal({ error: error.message, stack: error.stack }, 'Uncaught exception');
    shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
    logger.fatal({ reason }, 'Unhandled rejection');
});

// ===================================================================
// Start Server
// ===================================================================

const PORT = config.get('relay.port', 8080);
const HOST = config.get('relay.host', '0.0.0.0');

server.listen(PORT, HOST, () => {
    logger.info({ host: HOST, port: PORT, version: '2.0.0' }, 'Monarchs WebSocket Relay Server started');
    
    // Start Erlang connection
    connectToErlang();
});

logger.info('Monarchs Chat System - Production Relay Server v2.0.0');

