package com.monarchs.repository;

import com.monarchs.model.User;
import com.monarchs.model.UserStatus;
import com.monarchs.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for User entity operations.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * Find user by username
     */
    Optional<User> findByUsername(String username);
    
    /**
     * Find user by email
     */
    Optional<User> findByEmail(String email);
    
    /**
     * Check if username exists
     */
    boolean existsByUsername(String username);
    
    /**
     * Check if email exists
     */
    boolean existsByEmail(String email);
    
    /**
     * Find all users by status
     */
    List<User> findByStatus(UserStatus status);
    
    /**
     * Find all users by role
     */
    List<User> findByRole(Role role);
    
    /**
     * Find users by role and status
     */
    List<User> findByRoleAndStatus(Role role, UserStatus status);
    
    /**
     * Find online users
     */
    @Query("SELECT u FROM User u WHERE u.status = :status")
    List<User> findOnlineUsers(@Param("status") UserStatus status);
    
    /**
     * Count users by status
     */
    long countByStatus(UserStatus status);
    
    /**
     * Find banned users
     */
    @Query("SELECT u FROM User u WHERE u.banned = true")
    List<User> findBannedUsers();
    
    /**
     * Find users created after a certain date
     */
    List<User> findByCreatedAtAfter(Instant date);
    
    /**
     * Find users last login before a certain date
     */
    List<User> findByLastLoginBefore(Instant date);
    
    /**
     * Find users with username containing (case-insensitive)
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<User> searchByUsername(@Param("searchTerm") String searchTerm);
    
    /**
     * Check if any admin exists
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.role IN ('ADMIN', 'OWNER')")
    boolean existsAdmin();
    
    /**
     * Count online users
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.status = 'ONLINE'")
    long countOnline();
}

