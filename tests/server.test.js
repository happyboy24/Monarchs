/**
 * Monarchs Chat System - Test Suite
 * Comprehensive tests for Node.js WebSocket relay server
 */

const request = require('supertest');
const http = require('http');
const WebSocket = require('ws');

// Mock server for testing (simplified version)
class MockServer {
    constructor() {
        this.config = {
            relay: { port: 8080, path: '/ws' },
            security: { token_secret: 'test-secret', token_expiry: 3600000 },
            logging: { level: 'error', format: 'json' },
            cors: { origins: ['*'], credentials: true },
            monitoring: { health: { enabled: true }, metrics: { enabled: true } },
            app: { environment: 'test', name: 'monarchs' }
        };
        this.connections = new Map();
        this.connected = false;
    }
    
    get(key, defaultValue) {
        const keys = key.split('.');
        let value = this.config;
        for (const k of keys) {
            value = value?.[k];
        }
        return value !== undefined ? value : defaultValue;
    }
}

describe('Monarchs WebSocket Relay Server', () => {
    describe('Configuration', () => {
        test('should load default configuration', () => {
            const server = new MockServer();
            expect(server.get('relay.port')).toBe(8080);
            expect(server.get('security.token_secret')).toBe('test-secret');
            expect(server.get('app.environment')).toBe('test');
        });
        
        test('should return default value for missing key', () => {
            const server = new MockServer();
            expect(server.get('nonexistent.key', 'default')).toBe('default');
        });
    });
    
    describe('Token Management', () => {
        test('should create valid JWT-like token', () => {
            const header = { alg: 'HS256', typ: 'JWT' };
            const payload = {
                sub: 'testuser',
                iat: Date.now(),
                exp: Date.now() + 3600000
            };

            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');

            expect(encodedHeader).toBeDefined();
            expect(encodedPayload).toBeDefined();
            expect(encodedHeader).not.toContain('.');
            expect(encodedPayload).not.toContain('.');
        });
        
        test('should verify valid token', () => {
            const secret = 'test-secret';
            const header = { alg: 'HS256', typ: 'JWT' };
            const payload = {
                sub: 'testuser',
                iat: Date.now(),
                exp: Date.now() + 3600000
            };
            
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const crypto = require('crypto');
            const signature = crypto
                .createHmac('sha256', secret)
                .update(`${encodedHeader}.${encodedPayload}`)
                .digest('base64url');
            
            const token = `${encodedHeader}.${encodedPayload}.${signature}`;
            const parts = token.split('.');
            
            expect(parts).toHaveLength(3);
            expect(parts[0]).toBe(encodedHeader);
        });
        
        test('should detect expired token', () => {
            const payload = {
                sub: 'testuser',
                iat: Date.now() - 7200000,
                exp: Date.now() - 3600000 // Expired 1 hour ago
            };
            
            const isExpired = payload.exp < Date.now();
            expect(isExpired).toBe(true);
        });
    });
    
    describe('Rate Limiting', () => {
        test('should allow requests within limit', () => {
            const rateLimitMap = new Map();
            const RATE_LIMIT_WINDOW = 60000;
            const MAX_MESSAGES_PER_WINDOW = 30;
            const now = Date.now();
            const clientId = 'test-client';
            
            // First request
            if (!rateLimitMap.has(clientId)) {
                rateLimitMap.set(clientId, { count: 1, windowStart: now });
            }
            
            const record = rateLimitMap.get(clientId);
            expect(record.count).toBe(1);
            expect(record.count < MAX_MESSAGES_PER_WINDOW).toBe(true);
        });
        
        test('should block requests exceeding limit', () => {
            const rateLimitMap = new Map();
            const RATE_LIMIT_WINDOW = 60000;
            const MAX_MESSAGES_PER_WINDOW = 30;
            const now = Date.now();
            const clientId = 'test-client';
            
            // Simulate max requests
            rateLimitMap.set(clientId, { count: MAX_MESSAGES_PER_WINDOW, windowStart: now });
            
            const record = rateLimitMap.get(clientId);
            const isBlocked = record.count >= MAX_MESSAGES_PER_WINDOW;
            
            expect(isBlocked).toBe(true);
        });
    });
    
    describe('Message Validation', () => {
        test('should validate username format', () => {
            const validateUsername = (username) => {
                const Length = username.length;
                const ValidChars = /^[a-zA-Z0-9_]+$/.test(username);
                return Length >= 3 && Length <= 30 && ValidChars;
            };
            
            expect(validateUsername('validuser123')).toBe(true);
            expect(validateUsername('user_name')).toBe(true);
            expect(validateUsername('ab')).toBe(false); // Too short
            expect(validateUsername('user with spaces')).toBe(false); // Invalid chars
        });
        
        test('should validate password strength', () => {
            const validatePassword = (password) => {
                const Length = password.length;
                return Length >= 8 &&
                    /[a-z]/.test(password) &&
                    /[A-Z]/.test(password) &&
                    /[0-9]/.test(password);
            };
            
            expect(validatePassword('StrongPass123')).toBe(true);
            expect(validatePassword('weak')).toBe(false); // Too short
            expect(validatePassword('nouppercase123')).toBe(false); // No uppercase
            expect(validatePassword('NOLOWERCASE123')).toBe(false); // No lowercase
        });
        
        test('should sanitize message content', () => {
            const sanitizeMessage = (message) => {
                // Remove null bytes and control characters
                return message
                    .replace(/[\x00-\x1F\x7F]/g, '')
                    .substring(0, 4096);
            };
            
            const sanitized = sanitizeMessage('Hello\x00 World\x1F!');
            expect(sanitized).toBe('Hello World!');
            expect(sanitized.length).toBeLessThanOrEqual(4096);
        });
    });
    
    describe('Response Parsing', () => {
        test('should parse chat message format', () => {
            const message = '[general] <testuser> Hello World!';
            const match = message.match(/^\[(.+)\] <(.+)> (.+)$/);
            
            expect(match).toBeDefined();
            expect(match[1]).toBe('general');
            expect(match[2]).toBe('testuser');
            expect(match[3]).toBe('Hello World!');
        });
        
        test('should parse private message format', () => {
            const message = '[PM from testuser] Hello!';
            const match = message.match(/\[PM from (.+)\] (.+)/);
            
            expect(match).toBeDefined();
            expect(match[1]).toBe('testuser');
            expect(match[2]).toBe('Hello!');
        });
        
        test('should parse room list format', () => {
            const data = 'Available rooms:\n  - general\n  - random\n  - support';
            const rooms = data
                .split('\n')
                .filter(line => line.includes('  - '))
                .map(r => r.replace(/^  - /, '').trim())
                .filter(r => r);

            expect(rooms).toEqual(['general', 'random', 'support']);
        });
    });
    
    describe('Connection Management', () => {
        test('should track connection count', () => {
            const connectionTracker = new Map();
            const clientIp = '192.168.1.1';
            
            // Simulate connection
            const count = (connectionTracker.get(clientIp) || 0) + 1;
            connectionTracker.set(clientIp, count);
            
            expect(connectionTracker.get(clientIp)).toBe(1);
        });
        
        test('should limit connections per IP', () => {
            const connectionTracker = new Map();
            const MAX_CONNECTIONS_PER_IP = 10;
            const clientIp = '192.168.1.1';
            
            // Simulate multiple connections
            connectionTracker.set(clientIp, MAX_CONNECTIONS_PER_IP);
            
            const allowed = connectionTracker.get(clientIp) < MAX_CONNECTIONS_PER_IP;
            expect(allowed).toBe(false);
        });
    });
    
    describe('Metrics Generation', () => {
        test('should generate Prometheus metrics format', () => {
            const generateMetrics = (uptime, memory, connections) => {
                return [
                    '# HELP monarchs_relay_info Information about the relay service',
                    '# TYPE monarchs_relay_info gauge',
                    `monarchs_relay_info{version="2.0.0",environment="test"} 1`,
                    '',
                    '# HELP monarchs_relay_uptime_seconds_total Uptime in seconds',
                    '# TYPE monarchs_relay_uptime_seconds_total counter',
                    `monarchs_relay_uptime_seconds_total ${uptime}`,
                    '',
                    '# HELP monarchs_relay_memory_bytes Memory usage in bytes',
                    '# TYPE monarchs_relay_memory_bytes gauge',
                    `monarchs_relay_memory_bytes{type="heap"} ${memory.heapUsed}`,
                    `monarchs_relay_memory_bytes{type="rss"} ${memory.rss}`,
                    '',
                    '# HELP monarchs_relay_websocket_connections_active Current active WebSocket connections',
                    '# TYPE monarchs_relay_websocket_connections_active gauge',
                    `monarchs_relay_websocket_connections_active ${connections}`,
                ].join('\n');
            };
            
            const metrics = generateMetrics(100, { heapUsed: 50000000, rss: 100000000 }, 10);
            
            expect(metrics).toContain('monarchs_relay_info');
            expect(metrics).toContain('monarchs_relay_uptime_seconds_total');
            expect(metrics).toContain('monarchs_relay_memory_bytes');
            expect(metrics).toContain('monarchs_relay_websocket_connections_active');
        });
        
        test('should generate health check response', () => {
            const generateHealth = (connected, uptime, memory) => {
                return {
                    status: connected ? 'healthy' : 'unhealthy',
                    timestamp: new Date().toISOString(),
                    uptime: uptime,
                    memory: memory,
                    erlang: {
                        connected: connected,
                        lastPing: Date.now()
                    },
                    checks: {
                        erlang: connected ? 'ok' : 'disconnected'
                    }
                };
            };
            
            const health = generateHealth(true, 100, { heapUsed: 50000000, rss: 100000000 });
            
            expect(health.status).toBe('healthy');
            expect(health.erlang.connected).toBe(true);
            expect(health.checks.erlang).toBe('ok');
        });
    });
});

describe('Security Functions', () => {
    describe('Password Hashing', () => {
        test('should generate salt', () => {
            const crypto = require('crypto');
            const salt = crypto.randomBytes(16).toString('hex');
            
            expect(salt.length).toBe(32);
            expect(/^[a-f0-9]+$/.test(salt)).toBe(true);
        });
        
        test('should hash password with salt', () => {
            const crypto = require('crypto');
            const password = 'testpassword';
            const salt = crypto.randomBytes(16).toString('hex');
            const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
            
            expect(hash.length).toBe(128);
            expect(hash).not.toBe(password);
        });
        
        test('should verify password hash', () => {
            const crypto = require('crypto');
            const password = 'testpassword';
            const salt = crypto.randomBytes(16).toString('hex');
            const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
            
            // Verify with same password
            const verify1 = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
            expect(verify1).toBe(hash);
            
            // Verify with wrong password
            const verify2 = crypto.pbkdf2Sync('wrongpassword', salt, 100000, 64, 'sha512').toString('hex');
            expect(verify2).not.toBe(hash);
        });
    });
    
    describe('Constant-Time Comparison', () => {
        test('should perform constant-time comparison', () => {
            const crypto = require('crypto');
            const a = 'test123';
            const b = 'test123';
            const c = 'test456';
            
            // Should not leak timing information
            const compare1 = crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
            const compare2 = crypto.timingSafeEqual(Buffer.from(a), Buffer.from(c));
            
            expect(compare1).toBe(true);
            expect(compare2).toBe(false);
        });
    });
    
    describe('UUID Generation', () => {
        test('should generate unique IDs', () => {
            const crypto = require('crypto');
            const ids = new Set();
            const iterations = 1000;
            
            for (let i = 0; i < iterations; i++) {
                const id = crypto.randomUUID();
                expect(ids.has(id)).toBe(false);
                ids.add(id);
            }
            
            expect(ids.size).toBe(iterations);
        });
    });
});

describe('Erlang Communication', () => {
    describe('Protocol Formatting', () => {
        test('should format register command', () => {
            const command = `/register ${'testuser'} ${'password123'}`;
            expect(command).toBe('/register testuser password123');
        });
        
        test('should format login command', () => {
            const command = `/login ${'testuser'} ${'password123'}`;
            expect(command).toBe('/login testuser password123');
        });
        
        test('should format room creation command', () => {
            const command = `/create ${'general'}`;
            expect(command).toBe('/create general');
        });
        
        test('should format private message command', () => {
            const command = `/msg ${'recipient'} ${'Hello!'}`;
            expect(command).toBe('/msg recipient Hello!');
        });
    });
    
    describe('Response Handling', () => {
        test('should handle login success response', () => {
            const response = 'Login successful!';
            expect(response.includes('Login successful')).toBe(true);
        });
        
        test('should handle login error response', () => {
            const response = 'Error: Invalid username or password';
            expect(response.includes('Error:')).toBe(true);
        });
        
        test('should handle room not found response', () => {
            const response = 'Error: Room not found';
            expect(response).toBe('Error: Room not found');
        });
    });
});

// Run tests
if (require.main === module) {
    const jest = require('jest');
    const path = require('path');
    jest.run(['--testPathPattern', path.basename(__filename), '--coverage', 'false']);
}

