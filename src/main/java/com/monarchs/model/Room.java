package com.monarchs.model;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Room entity representing a chat room.
 * Maps to the rooms table in the database.
 */
@Entity
@Table(name = "rooms", indexes = {
    @Index(name = "idx_rooms_name", columnList = "name"),
    @Index(name = "idx_rooms_type", columnList = "type")
})
public class Room {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Room name is required")
    @Size(min = 1, max = 50, message = "Room name must be between 1 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_\\- ]+$", message = "Room name contains invalid characters")
    @Column(nullable = false, unique = true, length = 50)
    private String name;
    
    @Column(name = "description", length = 500)
    private String description;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RoomType type = RoomType.PUBLIC;
    
    @Column(name = "max_users")
    private Integer maxUsers;
    
    @Column(name = "settings", columnDefinition = "TEXT")
    private String settingsJson;
    
    @ElementCollection
    @CollectionTable(name = "room_users", joinColumns = @JoinColumn(name = "room_id"))
    @Column(name = "username")
    private Set<String> users = new HashSet<>();
    
    @Column(name = "is_active", nullable = false)
    private boolean active = true;
    
    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }
    
    // Default constructor for JPA
    public Room() {}
    
    // Constructor for creating new rooms
    public Room(String name, User owner) {
        this.name = name;
        this.owner = owner;
    }
    
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
    
    public User getOwner() {
        return owner;
    }
    
    public void setOwner(User owner) {
        this.owner = owner;
    }
    
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
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
    
    public String getSettingsJson() {
        return settingsJson;
    }
    
    public void setSettingsJson(String settingsJson) {
        this.settingsJson = settingsJson;
    }
    
    public Set<String> getUsers() {
        return users;
    }
    
    public void setUsers(Set<String> users) {
        this.users = users;
    }
    
    public boolean isActive() {
        return active;
    }
    
    public void setActive(boolean active) {
        this.active = active;
    }
    
    /**
     * Add a user to the room
     */
    public boolean addUser(String username) {
        if (maxUsers != null && users.size() >= maxUsers) {
            return false;
        }
        return users.add(username);
    }
    
    /**
     * Remove a user from the room
     */
    public boolean removeUser(String username) {
        return users.remove(username);
    }
    
    /**
     * Check if a user is in the room
     */
    public boolean hasUser(String username) {
        return users.contains(username);
    }
    
    /**
     * Check if the room is full
     */
    public boolean isFull() {
        return maxUsers != null && users.size() >= maxUsers;
    }
    
    /**
     * Get the current user count
     */
    public int getUserCount() {
        return users.size();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Room room)) return false;
        return id != null && id.equals(room.id);
    }
    
    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
    
    @Override
    public String toString() {
        return "Room{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", type=" + type +
                ", userCount=" + users.size() +
                ", active=" + active +
                '}';
    }
}

