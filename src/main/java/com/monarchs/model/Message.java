package com.monarchs.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

/**
 * Message entity representing a chat message.
 * Maps to the messages table in the database.
 */
@Entity
@Table(name = "messages", indexes = {
    @Index(name = "idx_messages_room", columnList = "room_name"),
    @Index(name = "idx_messages_sender", columnList = "sender"),
    @Index(name = "idx_messages_timestamp", columnList = "timestamp")
})
public class Message {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "message_id", nullable = false, unique = true, length = 50)
    private String messageId;
    
    @Column(name = "room_name", nullable = false, length = 50)
    private String roomName;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "room_id")
    private Room room;
    
    @Column(name = "sender", nullable = false, length = 30)
    private String sender;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "sender_id")
    private User senderUser;
    
    @NotBlank(message = "Message content is required")
    @Size(max = 4096, message = "Message must not exceed 4096 characters")
    @Column(nullable = false, length = 4096)
    private String content;
    
    @Column(nullable = false)
    private Instant timestamp;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private MessageType type = MessageType.ROOM;
    
    @Column(name = "recipient", length = 30)
    private String recipient;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "recipient_id")
    private User recipientUser;
    
    @Column(name = "metadata", columnDefinition = "TEXT")
    private String metadataJson;
    
    @Column(name = "is_deleted", nullable = false)
    private boolean deleted = false;
    
    @PrePersist
    protected void onCreate() {
        if (messageId == null) {
            messageId = generateMessageId();
        }
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
    
    // Default constructor for JPA
    public Message() {}
    
    // Constructor for creating new messages
    public Message(String roomName, String sender, String content) {
        this.roomName = roomName;
        this.sender = sender;
        this.content = content;
        this.timestamp = Instant.now();
        this.messageId = generateMessageId();
        this.type = MessageType.ROOM;
    }
    
    /**
     * Generate a unique message ID
     */
    private String generateMessageId() {
        return System.currentTimeMillis() + "-" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getMessageId() {
        return messageId;
    }
    
    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }
    
    public String getRoomName() {
        return roomName;
    }
    
    public void setRoomName(String roomName) {
        this.roomName = roomName;
    }
    
    public Room getRoom() {
        return room;
    }
    
    public void setRoom(Room room) {
        this.room = room;
    }
    
    public String getSender() {
        return sender;
    }
    
    public void setSender(String sender) {
        this.sender = sender;
    }
    
    public User getSenderUser() {
        return senderUser;
    }
    
    public void setSenderUser(User senderUser) {
        this.senderUser = senderUser;
    }
    
    public String getContent() {
        return content;
    }
    
    public void setContent(String content) {
        this.content = content;
    }
    
    public Instant getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
    
    public MessageType getType() {
        return type;
    }
    
    public void setType(MessageType type) {
        this.type = type;
    }
    
    public String getRecipient() {
        return recipient;
    }
    
    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }
    
    public User getRecipientUser() {
        return recipientUser;
    }
    
    public void setRecipientUser(User recipientUser) {
        this.recipientUser = recipientUser;
    }
    
    public String getMetadataJson() {
        return metadataJson;
    }
    
    public void setMetadataJson(String metadataJson) {
        this.metadataJson = metadataJson;
    }
    
    public boolean isDeleted() {
        return deleted;
    }
    
    public void setDeleted(boolean deleted) {
        this.deleted = deleted;
    }
    
    /**
     * Check if this is a private message
     */
    public boolean isPrivate() {
        return type == MessageType.PRIVATE;
    }
    
    /**
     * Sanitize message content to prevent injection attacks
     */
    public static String sanitize(String message) {
        if (message == null) {
            return "";
        }
        // Remove null bytes and control characters, limit length
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < message.length() && i < 4096; i++) {
            char c = message.charAt(i);
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 126) || c >= 128) {
                sb.append(c);
            }
        }
        return sb.toString();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Message message)) return false;
        return id != null && id.equals(message.id);
    }
    
    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
    
    @Override
    public String toString() {
        return "Message{" +
                "id=" + id +
                ", messageId='" + messageId + '\'' +
                ", roomName='" + roomName + '\'' +
                ", sender='" + sender + '\'' +
                ", type=" + type +
                ", timestamp=" + timestamp +
                '}';
    }
}

