package com.monarchs.dto;

import com.monarchs.model.Role;
import com.monarchs.model.UserStatus;

import java.time.Instant;

/**
 * Data Transfer Object for User entity.
 */
public class UserDto {
    
    private Long id;
    private String username;
    private String email;
    private UserStatus status;
    private Role role;
    private boolean banned;
    private String banReason;
    private Instant createdAt;
    private Instant lastLogin;
    private String currentRoom;
    
    // Default constructor
    public UserDto() {}
    
    // Constructor from User entity
    public UserDto(Long id, String username, String email, UserStatus status, Role role, 
                   boolean banned, Instant createdAt, Instant lastLogin) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.status = status;
        this.role = role;
        this.banned = banned;
        this.createdAt = createdAt;
        this.lastLogin = lastLogin;
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
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public UserStatus getStatus() {
        return status;
    }
    
    public void setStatus(UserStatus status) {
        this.status = status;
    }
    
    public Role getRole() {
        return role;
    }
    
    public void setRole(Role role) {
        this.role = role;
    }
    
    public boolean isBanned() {
        return banned;
    }
    
    public void setBanned(boolean banned) {
        this.banned = banned;
    }
    
    public String getBanReason() {
        return banReason;
    }
    
    public void setBanReason(String banReason) {
        this.banReason = banReason;
    }
    
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    
    public Instant getLastLogin() {
        return lastLogin;
    }
    
    public void setLastLogin(Instant lastLogin) {
        this.lastLogin = lastLogin;
    }
    
    public String getCurrentRoom() {
        return currentRoom;
    }
    
    public void setCurrentRoom(String currentRoom) {
        this.currentRoom = currentRoom;
    }
    
    /**
     * Builder class for UserDto
     */
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private final UserDto dto = new UserDto();
        
        public Builder id(Long id) {
            dto.id = id;
            return this;
        }
        
        public Builder username(String username) {
            dto.username = username;
            return this;
        }
        
        public Builder email(String email) {
            dto.email = email;
            return this;
        }
        
        public Builder status(UserStatus status) {
            dto.status = status;
            return this;
        }
        
        public Builder role(Role role) {
            dto.role = role;
            return this;
        }
        
        public Builder banned(boolean banned) {
            dto.banned = banned;
            return this;
        }
        
        public Builder banReason(String banReason) {
            dto.banReason = banReason;
            return this;
        }
        
        public Builder createdAt(Instant createdAt) {
            dto.createdAt = createdAt;
            return this;
        }
        
        public Builder lastLogin(Instant lastLogin) {
            dto.lastLogin = lastLogin;
            return this;
        }
        
        public Builder currentRoom(String currentRoom) {
            dto.currentRoom = currentRoom;
            return this;
        }
        
        public UserDto build() {
            return dto;
        }
    }
}

