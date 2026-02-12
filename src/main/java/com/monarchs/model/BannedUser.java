package com.monarchs.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * BannedUser entity representing a banned user record.
 * Maps to the banned_users table in the database.
 */
@Entity
@Table(name = "banned_users", indexes = {
    @Index(name = "idx_banned_username", columnList = "username"),
    @Index(name = "idx_banned_ip", columnList = "ip_address")
})
public class BannedUser {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 30)
    private String username;
    
    @Column(name = "banned_by", length = 30)
    private String bannedBy;
    
    @Column(name = "reason", nullable = false, length = 500)
    private String reason;
    
    @Column(name = "banned_at", nullable = false)
    private Instant bannedAt;
    
    @Column(name = "expires_at")
    private Instant expiresAt;
    
    @Column(name = "ip_address", length = 45)
    private String ipAddress;
    
    @PrePersist
    protected void onCreate() {
        if (bannedAt == null) {
            bannedAt = Instant.now();
        }
    }
    
    // Default constructor for JPA
    public BannedUser() {}
    
    // Constructor for creating new ban records
    public BannedUser(String username, String bannedBy, String reason) {
        this.username = username;
        this.bannedBy = bannedBy;
        this.reason = reason;
        this.bannedAt = Instant.now();
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getBannedBy() {
        return bannedBy;
    }
    
    public void setBannedBy(String bannedBy) {
        this.bannedBy = bannedBy;
    }
    
    public String getReason() {
        return reason;
    }
    
    public void setReason(String reason) {
        this.reason = reason;
    }
    
    public Instant getBannedAt() {
        return bannedAt;
    }
    
    public void setBannedAt(Instant bannedAt) {
        this.bannedAt = bannedAt;
    }
    
    public Instant getExpiresAt() {
        return expiresAt;
    }
    
    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    
    /**
     * Check if the ban has expired
     */
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return Instant.now().isAfter(expiresAt);
    }
    
    /**
     * Check if this is a permanent ban
     */
    public boolean isPermanent() {
        return expiresAt == null;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof BannedUser bannedUser)) return false;
        return id != null && id.equals(bannedUser.id);
    }
    
    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
    
    @Override
    public String toString() {
        return "BannedUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", bannedBy='" + bannedBy + '\'' +
                ", reason='" + reason + '\'' +
                ", bannedAt=" + bannedAt +
                ", expiresAt=" + expiresAt +
                '}';
    }
}

