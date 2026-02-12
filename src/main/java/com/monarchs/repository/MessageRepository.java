package com.monarchs.repository;

import com.monarchs.model.Message;
import com.monarchs.model.MessageType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

/**
 * Repository interface for Message entity operations.
 */
@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {
    
    /**
     * Find message by message ID
     */
    @Query("SELECT m FROM Message m WHERE m.messageId = :messageId")
    Message findByMessageId(@Param("messageId") String messageId);
    
    /**
     * Find messages by room name
     */
    List<Message> findByRoomNameOrderByTimestampAsc(String roomName);
    
    /**
     * Find messages by room name with pagination
     */
    Page<Message> findByRoomNameOrderByTimestampDesc(String roomName, Pageable pageable);
    
    /**
     * Find messages by sender
     */
    List<Message> findBySenderOrderByTimestampDesc(String sender);
    
    /**
     * Find messages by type
     */
    List<Message> findByTypeOrderByTimestampDesc(MessageType type);
    
    /**
     * Find private messages between two users
     */
    @Query("SELECT m FROM Message m WHERE (m.sender = :user1 AND m.recipient = :user2) OR (m.sender = :user2 AND m.recipient = :user1) ORDER BY m.timestamp ASC")
    List<Message> findPrivateMessagesBetweenUsers(@Param("user1") String user1, @Param("user2") String user2);
    
    /**
     * Find messages in room after a certain time
     */
    @Query("SELECT m FROM Message m WHERE m.roomName = :roomName AND m.timestamp > :since ORDER BY m.timestamp ASC")
    List<Message> findMessagesInRoomSince(@Param("roomName") String roomName, @Param("since") Instant since);
    
    /**
     * Count messages in a room
     */
    long countByRoomName(String roomName);
    
    /**
     * Count messages by sender
     */
    long countBySender(String sender);
    
    /**
     * Delete old messages (for cleanup)
     */
    void deleteByTimestampBefore(Instant timestamp);
    
    /**
     * Find recent messages in a room
     */
    @Query("SELECT m FROM Message m WHERE m.roomName = :roomName ORDER BY m.timestamp DESC")
    List<Message> findRecentMessagesInRoom(@Param("roomName") String roomName, Pageable pageable);
}

