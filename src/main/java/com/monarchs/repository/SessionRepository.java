package com.monarchs.repository;

import com.monarchs.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Session entity operations.
 */
@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {
    
    /**
     * Find session by token
     */
    Optional<Session> findByToken(String token);
    
    /**
     * Check if token exists
     */
    boolean existsByToken(String token);
    
    /**
     * Find sessions by username
     */
    List<Session> findByUsernameOrderByCreatedAtDesc(String username);
    
    /**
     * Find valid (non-expired) sessions for a user
     */
    @Query("SELECT s FROM Session s WHERE s.username = :username AND s.expiresAt > :now ORDER BY s.createdAt DESC")
    List<Session> findValidSessionsByUsername(@Param("username") String username, @Param("now") Instant now);
    
    /**
     * Delete expired sessions
     */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :now")
    int deleteExpiredSessions(@Param("now") Instant now);
    
    /**
     * Delete all sessions for a user
     */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.username = :username")
    int deleteAllByUsername(@Param("username") String username);
    
    /**
     * Delete session by token
     */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.token = :token")
    int deleteByToken(@Param("token") String token);
    
    /**
     * Count sessions for a user
     */
    long countByUsername(String username);
    
    /**
     * Find sessions by IP address
     */
    List<Session> findByIpAddress(String ipAddress);
    
    /**
     * Update last activity for a session
     */
    @Modifying
    @Query("UPDATE Session s SET s.lastActivity = :now WHERE s.token = :token")
    int updateLastActivity(@Param("token") String token, @Param("now") Instant now);
}

