package com.monarchs.repository;

import com.monarchs.model.BannedUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for BannedUser entity operations.
 */
@Repository
public interface BannedUserRepository extends JpaRepository<BannedUser, Long> {
    
    /**
     * Find banned user by username
     */
    Optional<BannedUser> findByUsername(String username);
    
    /**
     * Check if user is banned
     */
    boolean existsByUsername(String username);
    
    /**
     * Find all permanent bans (no expiry)
     */
    List<BannedUser> findByExpiresAtIsNull();
    
    /**
     * Find active bans (not expired)
     */
    @Query("SELECT b FROM BannedUser b WHERE b.expiresAt IS NULL OR b.expiresAt > :now")
    List<BannedUser> findActiveBans(@Param("now") Instant now);
    
    /**
     * Find expired bans (for cleanup)
     */
    @Query("SELECT b FROM BannedUser b WHERE b.expiresAt IS NOT NULL AND b.expiresAt < :now")
    List<BannedUser> findExpiredBans(@Param("now") Instant now);
    
    /**
     * Delete expired bans
     */
    @Modifying
    @Query("DELETE FROM BannedUser b WHERE b.expiresAt IS NOT NULL AND b.expiresAt < :now")
    int deleteExpiredBans(@Param("now") Instant now);
    
    /**
     * Find bans by admin
     */
    List<BannedUser> findByBannedBy(String bannedBy);
    
    /**
     * Find bans by IP address
     */
    List<BannedUser> findByIpAddress(String ipAddress);
    
    /**
     * Count active bans
     */
    @Query("SELECT COUNT(b) FROM BannedUser b WHERE b.expiresAt IS NULL OR b.expiresAt > :now")
    long countActiveBans(@Param("now") Instant now);
}

