package com.monarchs.dto;

import com.monarchs.model.RoomType;

import java.time.Instant;
import java.util.Set;

/**
 * Data Transfer Object for Room entity.
 */
public class RoomDto {
    
    private Long id;
    private String name;
    private String description;
    private String owner;
    private RoomType type;
    private Integer maxUsers;
    private int currentUsers;
    private Set<String> users;
    private boolean active;
    private Instant createdAt;
    
    // Default constructor
    public RoomDto() {}
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public String getOwner() {
        return owner;
    }
    
    public void setOwner(String owner) {
        this.owner = owner;
    }
    
    public RoomType getType() {
        return type;
    }
    
    public void setType(RoomType type) {
        this.type = type;
    }
    
    public Integer getMaxUsers() {
        return maxUsers;
    }
    
    public void setMaxUsers(Integer maxUsers) {
        this.maxUsers = maxUsers;
    }
    
    public int getCurrentUsers() {
        return currentUsers;
    }
    
    public void setCurrentUsers(int currentUsers) {
        this.currentUsers = currentUsers;
    }
    
    public Set<String> getUsers() {
        return users;
    }
    
    public void setUsers(Set<String> users) {
        this.users = users;
        this.currentUsers = users != null ? users.size() : 0;
    }
    
    public boolean isActive() {
        return active;
    }
    
    public void setActive(boolean active) {
        this.active = active;
    }
    
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    
    public boolean isFull() {
        return maxUsers != null && currentUsers >= maxUsers;
    }
    
    /**
     * Builder class for RoomDto
     */
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private final RoomDto dto = new RoomDto();
        
        public Builder id(Long id) {
            dto.id = id;
            return this;
        }
        
        public Builder name(String name) {
            dto.name = name;
            return this;
        }
        
        public Builder description(String description) {
            dto.description = description;
            return this;
        }
        
        public Builder owner(String owner) {
            dto.owner = owner;
            return this;
        }
        
        public Builder type(RoomType type) {
            dto.type = type;
            return this;
        }
        
        public Builder maxUsers(Integer maxUsers) {
            dto.maxUsers = maxUsers;
            return this;
        }
        
        public Builder active(boolean active) {
            dto.active = active;
            return this;
        }
        
        public Builder createdAt(Instant createdAt) {
            dto.createdAt = createdAt;
            return this;
        }
        
        public RoomDto build() {
            return dto;
        }
    }
}

