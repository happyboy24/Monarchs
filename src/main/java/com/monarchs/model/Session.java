package com.monarchs.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Session entity representing a user session/token.
 * Maps to the sessions table in the database.
 */
@Entity
@Table(name = "sessions", indexes = {
    @Index(name = "idx_sessions_token", columnList = "token"),
    @Index(name = "idx_sessions_user", columnList = "username"),
    @Index(name = "idx_sessions_expires", columnList = "expires_at")
})
public class Session {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 256)
    private String token;
    
    @Column(name = "username", nullable = false, length = 30)
    private String username;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    
    @Column(name = "last_activity")
    private Instant lastActivity;
    
    @Column(name = "ip_address", length = 45)
    private String ipAddress;
    
    @Column(name = "user_agent", length = 500)
    private String userAgent;
    
    @Column(name = "socket_id", length = 100)
    private String socketId;
    
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (lastActivity == null) {
            lastActivity = createdAt;
        }
    }
    
    // Default constructor for JPA
    public Session() {}
    
    // Constructor for creating new sessions
    public Session(String username, String token, int expirySeconds) {
        this.username = username;
        this.token = token;
        this.createdAt = Instant.now();
        this.expiresAt = this.createdAt.plusSeconds(expirySeconds);
        this.lastActivity = this.createdAt;
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getToken() {
        return token;
    }
    
    public void setToken(String token) {
        this.token = token;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    
    public Instant getExpiresAt() {
        return expiresAt;
    }
    
    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }
    
    public Instant getLastActivity() {
        return lastActivity;
    }
    
    public void setLastActivity(Instant lastActivity) {
        this.lastActivity = lastActivity;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    
    public String getUserAgent() {
        return userAgent;
    }
    
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }
    
    public String getSocketId() {
        return socketId;
    }
    
    public void setSocketId(String socketId) {
        this.socketId = socketId;
    }
    
    /**
     * Check if the session has expired
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
    
    /**
     * Check if the session is valid (not expired)
     */
    public boolean isValid() {
        return !isExpired();
    }
    
    /**
     * Update last activity timestamp
     */
    public void updateActivity() {
        this.lastActivity = Instant.now();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Session session)) return false;
        return id != null && id.equals(session.id);
    }
    
    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
    
    @Override
    public String toString() {
        return "Session{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", valid=" + isValid() +
                '}';
    }
}

