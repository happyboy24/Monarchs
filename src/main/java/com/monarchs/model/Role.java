package com.monarchs.model;

/**
 * User role enum representing the permission hierarchy in the chat system.
 * Roles are ordered from lowest to highest privilege.
 */
public enum Role {
    /**
     * Regular user with basic chat functionality
     */
    USER,
    
    /**
     * Moderator with room management capabilities
     */
    MODERATOR,
    
    /**
     * Administrator with user management capabilities
     */
    ADMIN,
    
    /**
     * Owner with full system control including server shutdown
     */
    OWNER;
    
    /**
     * Check if this role has admin privileges (admin or owner)
     */
    public boolean isAdmin() {
        return this == ADMIN || this == OWNER;
    }
    
    /**
     * Check if this role has owner privileges
     */
    public boolean isOwner() {
        return this == OWNER;
    }
    
    /**
     * Check if this role can kick users from rooms
     */
    public boolean canKick() {
        return this == MODERATOR || this == ADMIN || this == OWNER;
    }
    
    /**
     * Check if this role can ban users
     */
    public boolean canBan() {
        return this == ADMIN || this == OWNER;
    }
    
    /**
     * Check if this role can promote/demote users
     */
    public boolean canManageUsers() {
        return this == ADMIN || this == OWNER;
    }
    
    /**
     * Check if this role can shutdown the server
     */
    public boolean canShutdown() {
        return this == OWNER;
    }
}

