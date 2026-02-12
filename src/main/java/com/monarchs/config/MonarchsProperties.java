package com.monarchs.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for the Monarchs application.
 * Maps to the 'monarchs' prefix in application.yml.
 */
@Component
@ConfigurationProperties(prefix = "monarchs")
public class MonarchsProperties {
    
    private App app = new App();
    private Backend backend = new Backend();
    private Security security = new Security();
    private Password password = new Password();
    private Username username = new Username();
    private WebSocket websocket = new WebSocket();
    private Logging logging = new Logging();
    private Monitoring monitoring = new Monitoring();
    private Cors cors = new Cors();
    private Features features = new Features();
    private Admin admin = new Admin();
    
    // Getters and Setters
    public App getApp() {
        return app;
    }
    
    public void setApp(App app) {
        this.app = app;
    }
    
    public Backend getBackend() {
        return backend;
    }
    
    public void setBackend(Backend backend) {
        this.backend = backend;
    }
    
    public Security getSecurity() {
        return security;
    }
    
    public void setSecurity(Security security) {
        this.security = security;
    }
    
    public Password getPassword() {
        return password;
    }
    
    public void setPassword(Password password) {
        this.password = password;
    }
    
    public Username getUsername() {
        return username;
    }
    
    public void setUsername(Username username) {
        this.username = username;
    }
    
    public WebSocket getWebsocket() {
        return websocket;
    }
    
    public void setWebsocket(WebSocket websocket) {
        this.websocket = websocket;
    }
    
    public Logging getLogging() {
        return logging;
    }
    
    public void setLogging(Logging logging) {
        this.logging = logging;
    }
    
    public Monitoring getMonitoring() {
        return monitoring;
    }
    
    public void setMonitoring(Monitoring monitoring) {
        this.monitoring = monitoring;
    }
    
    public Cors getCors() {
        return cors;
    }
    
    public void setCors(Cors cors) {
        this.cors = cors;
    }
    
    public Features getFeatures() {
        return features;
    }
    
    public void setFeatures(Features features) {
        this.features = features;
    }
    
    public Admin getAdmin() {
        return admin;
    }
    
    public void setAdmin(Admin admin) {
        this.admin = admin;
    }
    
    // Nested configuration classes
    public static class App {
        private String name = "monarchs";
        private String version = "2.0.0";
        private String environment = "development";
        
        public String getName() {
            return name;
        }
        
        public void setName(String name) {
            this.name = name;
        }
        
        public String getVersion() {
            return version;
        }
        
        public void setVersion(String version) {
            this.version = version;
        }
        
        public String getEnvironment() {
            return environment;
        }
        
        public void setEnvironment(String environment) {
            this.environment = environment;
        }
    }
    
    public static class Backend {
        private String host = "0.0.0.0";
        private int port = 5678;
        private int maxConnections = 10000;
        
        public String getHost() {
            return host;
        }
        
        public void setHost(String host) {
            this.host = host;
        }
        
        public int getPort() {
            return port;
        }
        
        public void setPort(int port) {
            this.port = port;
        }
        
        public int getMaxConnections() {
            return maxConnections;
        }
        
        public void setMaxConnections(int maxConnections) {
            this.maxConnections = maxConnections;
        }
    }
    
    public static class Security {
        private int bcryptCost = 12;
        private int tokenExpiry = 3600;
        private int refreshTokenExpiry = 86400;
        private String tokenSecret = "your-256-bit-secret-key-change-in-production";
        private int maxLoginAttempts = 5;
        private long rateLimitWindowMs = 60000;
        private long banDurationMs = 300000;
        
        public int getBcryptCost() {
            return bcryptCost;
        }
        
        public void setBcryptCost(int bcryptCost) {
            this.bcryptCost = bcryptCost;
        }
        
        public int getTokenExpiry() {
            return tokenExpiry;
        }
        
        public void setTokenExpiry(int tokenExpiry) {
            this.tokenExpiry = tokenExpiry;
        }
        
        public int getRefreshTokenExpiry() {
            return refreshTokenExpiry;
        }
        
        public void setRefreshTokenExpiry(int refreshTokenExpiry) {
            this.refreshTokenExpiry = refreshTokenExpiry;
        }
        
        public String getTokenSecret() {
            return tokenSecret;
        }
        
        public void setTokenSecret(String tokenSecret) {
            this.tokenSecret = tokenSecret;
        }
        
        public int getMaxLoginAttempts() {
            return maxLoginAttempts;
        }
        
        public void setMaxLoginAttempts(int maxLoginAttempts) {
            this.maxLoginAttempts = maxLoginAttempts;
        }
        
        public long getRateLimitWindowMs() {
            return rateLimitWindowMs;
        }
        
        public void setRateLimitWindowMs(long rateLimitWindowMs) {
            this.rateLimitWindowMs = rateLimitWindowMs;
        }
        
        public long getBanDurationMs() {
            return banDurationMs;
        }
        
        public void setBanDurationMs(long banDurationMs) {
            this.banDurationMs = banDurationMs;
        }
    }
    
    public static class Password {
        private int minLength = 8;
        private int maxLength = 128;
        private boolean requireUppercase = true;
        private boolean requireLowercase = true;
        private boolean requireNumbers = true;
        private boolean requireSpecial = false;
        
        public int getMinLength() {
            return minLength;
        }
        
        public void setMinLength(int minLength) {
            this.minLength = minLength;
        }
        
        public int getMaxLength() {
            return maxLength;
        }
        
        public void setMaxLength(int maxLength) {
            this.maxLength = maxLength;
        }
        
        public boolean isRequireUppercase() {
            return requireUppercase;
        }
        
        public void setRequireUppercase(boolean requireUppercase) {
            this.requireUppercase = requireUppercase;
        }
        
        public boolean isRequireLowercase() {
            return requireLowercase;
        }
        
        public void setRequireLowercase(boolean requireLowercase) {
            this.requireLowercase = requireLowercase;
        }
        
        public boolean isRequireNumbers() {
            return requireNumbers;
        }
        
        public void setRequireNumbers(boolean requireNumbers) {
            this.requireNumbers = requireNumbers;
        }
        
        public boolean isRequireSpecial() {
            return requireSpecial;
        }
        
        public void setRequireSpecial(boolean requireSpecial) {
            this.requireSpecial = requireSpecial;
        }
    }
    
    public static class Username {
        private int minLength = 3;
        private int maxLength = 30;
        private String pattern = "^[a-zA-Z0-9_]+$";
        
        public int getMinLength() {
            return minLength;
        }
        
        public void setMinLength(int minLength) {
            this.minLength = minLength;
        }
        
        public int getMaxLength() {
            return maxLength;
        }
        
        public void setMaxLength(int maxLength) {
            this.maxLength = maxLength;
        }
        
        public String getPattern() {
            return pattern;
        }
        
        public void setPattern(String pattern) {
            this.pattern = pattern;
        }
    }
    
    public static class WebSocket {
        private boolean enabled = true;
        private String path = "/ws";
        private long heartbeatIntervalMs = 30000;
        private long connectionTimeoutMs = 60000;
        private int maxPayloadSize = 65536;
        
        public boolean isEnabled() {
            return enabled;
        }
        
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
        
        public String getPath() {
            return path;
        }
        
        public void setPath(String path) {
            this.path = path;
        }
        
        public long getHeartbeatIntervalMs() {
            return heartbeatIntervalMs;
        }
        
        public void setHeartbeatIntervalMs(long heartbeatIntervalMs) {
            this.heartbeatIntervalMs = heartbeatIntervalMs;
        }
        
        public long getConnectionTimeoutMs() {
            return connectionTimeoutMs;
        }
        
        public void setConnectionTimeoutMs(long connectionTimeoutMs) {
            this.connectionTimeoutMs = connectionTimeoutMs;
        }
        
        public int getMaxPayloadSize() {
            return maxPayloadSize;
        }
        
        public void setMaxPayloadSize(int maxPayloadSize) {
            this.maxPayloadSize = maxPayloadSize;
        }
    }
    
    public static class Logging {
        private String level = "info";
        private String format = "json";
        private Audit audit = new Audit();
        
        public String getLevel() {
            return level;
        }
        
        public void setLevel(String level) {
            this.level = level;
        }
        
        public String getFormat() {
            return format;
        }
        
        public void setFormat(String format) {
            this.format = format;
        }
        
        public Audit getAudit() {
            return audit;
        }
        
        public void setAudit(Audit audit) {
            this.audit = audit;
        }
        
        public static class Audit {
            private boolean enabled = true;
            
            public boolean isEnabled() {
                return enabled;
            }
            
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }
    }
    
    public static class Monitoring {
        private Health health = new Health();
        private Metrics metrics = new Metrics();
        
        public Health getHealth() {
            return health;
        }
        
        public void setHealth(Health health) {
            this.health = health;
        }
        
        public Metrics getMetrics() {
            return metrics;
        }
        
        public void setMetrics(Metrics metrics) {
            this.metrics = metrics;
        }
        
        public static class Health {
            private boolean enabled = true;
            private String path = "/health";
            
            public boolean isEnabled() {
                return enabled;
            }
            
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
            
            public String getPath() {
                return path;
            }
            
            public void setPath(String path) {
                this.path = path;
            }
        }
        
        public static class Metrics {
            private boolean enabled = true;
            private String path = "/metrics";
            private boolean prometheus = true;
            
            public boolean isEnabled() {
                return enabled;
            }
            
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
            
            public String getPath() {
                return path;
            }
            
            public void setPath(String path) {
                this.path = path;
            }
            
            public boolean isPrometheus() {
                return prometheus;
            }
            
            public void setPrometheus(boolean prometheus) {
                this.prometheus = prometheus;
            }
        }
    }
    
    public static class Cors {
        private boolean enabled = true;
        private String allowedOrigins = "*";
        private String allowedMethods = "GET,POST,OPTIONS";
        private boolean allowCredentials = true;
        private long maxAge = 86400;
        
        public boolean isEnabled() {
            return enabled;
        }
        
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
        
        public String getAllowedOrigins() {
            return allowedOrigins;
        }
        
        public void setAllowedOrigins(String allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }
        
        public String getAllowedMethods() {
            return allowedMethods;
        }
        
        public void setAllowedMethods(String allowedMethods) {
            this.allowedMethods = allowedMethods;
        }
        
        public boolean isAllowCredentials() {
            return allowCredentials;
        }
        
        public void setAllowCredentials(boolean allowCredentials) {
            this.allowCredentials = allowCredentials;
        }
        
        public long getMaxAge() {
            return maxAge;
        }
        
        public void setMaxAge(long maxAge) {
            this.maxAge = maxAge;
        }
    }
    
    public static class Features {
        private boolean privateMessaging = true;
        private boolean userRoomCreation = true;
        private boolean guestAccess = false;
        private boolean endToEndEncryption = false;
        
        public boolean isPrivateMessaging() {
            return privateMessaging;
        }
        
        public void setPrivateMessaging(boolean privateMessaging) {
            this.privateMessaging = privateMessaging;
        }
        
        public boolean isUserRoomCreation() {
            return userRoomCreation;
        }
        
        public void setUserRoomCreation(boolean userRoomCreation) {
            this.userRoomCreation = userRoomCreation;
        }
        
        public boolean isGuestAccess() {
            return guestAccess;
        }
        
        public void setGuestAccess(boolean guestAccess) {
            this.guestAccess = guestAccess;
        }
        
        public boolean isEndToEndEncryption() {
            return endToEndEncryption;
        }
        
        public void setEndToEndEncryption(boolean endToEndEncryption) {
            this.endToEndEncryption = endToEndEncryption;
        }
    }
    
    public static class Admin {
        private boolean enabled = true;
        private String adminSecret = "monarchs_admin_secret_2024";
        
        public boolean isEnabled() {
            return enabled;
        }
        
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
        
        public String getAdminSecret() {
            return adminSecret;
        }
        
        public void setAdminSecret(String adminSecret) {
            this.adminSecret = adminSecret;
        }
    }
}

