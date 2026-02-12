package com.monarchs.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.Map;
import java.util.HashMap;

/**
 * AuditLog entity for tracking security and system events.
 * Maps to the audit_log table in the database.
 */
@Entity
@Table(name = "audit_log", indexes = {
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    @Index(name = "idx_audit_event", columnList = "event_type"),
    @Index(name = "idx_audit_user", columnList = "username")
})
public class AuditLog {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;
    
    @Column(name = "username", length = 30)
    private String username;
    
    @Column(name = "ip_address", length = 45)
    private String ipAddress;
    
    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;
    
    @Column(name = "details", columnDefinition = "TEXT")
    private String detailsJson;
    
    @Column(name = "success", nullable = false)
    private boolean success = true;
    
    @Column(name = "failure_reason", length = 500)
    private String failureReason;
    
    @PrePersist
    protected void onCreate() {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
    
    // Default constructor for JPA
    public AuditLog() {}
    
    // Constructor for creating audit entries
    public AuditLog(String eventType, String username) {
        this.eventType = eventType;
        this.username = username;
        this.timestamp = Instant.now();
    }
    
    // Static factory methods for common events
    public static AuditLog register(String username, boolean success) {
        AuditLog log = new AuditLog("REGISTER", username);
        log.setSuccess(success);
        return log;
    }
    
    public static AuditLog login(String username, String ipAddress, boolean success) {
        AuditLog log = new AuditLog("LOGIN", username);
        log.setIpAddress(ipAddress);
        log.setSuccess(success);
        if (!success) {
            log.setFailureReason("Invalid credentials");
        }
        return log;
    }
    
    public static AuditLog logout(String username) {
        return new AuditLog("LOGOUT", username);
    }
    
    public static AuditLog ban(String adminUsername, String targetUsername, String reason) {
        AuditLog log = new AuditLog("BAN", adminUsername);
        Map<String, String> details = new HashMap<>();
        details.put("target", targetUsername);
        details.put("reason", reason);
        log.setDetailsJson(mapToJson(details));
        return log;
    }
    
    public static AuditLog unban(String adminUsername, String targetUsername) {
        AuditLog log = new AuditLog("UNBAN", adminUsername);
        Map<String, String> details = new HashMap<>();
        details.put("target", targetUsername);
        log.setDetailsJson(mapToJson(details));
        return log;
    }
    
    public static AuditLog kick(String adminUsername, String targetUsername) {
        AuditLog log = new AuditLog("KICK", adminUsername);
        Map<String, String> details = new HashMap<>();
        details.put("target", targetUsername);
        log.setDetailsJson(mapToJson(details));
        return log;
    }
    
    public static AuditLog promote(String adminUsername, String targetUsername, String newRole) {
        AuditLog log = new AuditLog("PROMOTE", adminUsername);
        Map<String, String> details = new HashMap<>();
        details.put("target", targetUsername);
        details.put("new_role", newRole);
        log.setDetailsJson(mapToJson(details));
        return log;
    }
    
    public static AuditLog demote(String adminUsername, String targetUsername) {
        AuditLog log = new AuditLog("DEMOTE", adminUsername);
        Map<String, String> details = new HashMap<>();
        details.put("target", targetUsername);
        log.setDetailsJson(mapToJson(details));
        return log;
    }
    
    private static String mapToJson(Map<String, String> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(entry.getKey()).append("\":\"")
             .append(entry.getValue()).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getEventType() {
        return eventType;
    }
    
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    
    public Instant getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getDetailsJson() {
        return detailsJson;
    }
    
    public void setDetailsJson(String detailsJson) {
        this.detailsJson = detailsJson;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public String getFailureReason() {
        return failureReason;
    }
    
    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuditLog auditLog)) return false;
        return id != null && id.equals(auditLog.id);
    }
    
    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}

