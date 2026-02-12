package com.monarchs.repository;

import com.monarchs.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

/**
 * Repository interface for AuditLog entity operations.
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    
    /**
     * Find audit logs by event type
     */
    List<AuditLog> findByEventTypeOrderByTimestampDesc(String eventType);
    
    /**
     * Find audit logs by username
     */
    List<AuditLog> findByUsernameOrderByTimestampDesc(String username);
    
    /**
     * Find audit logs by IP address
     */
    List<AuditLog> findByIpAddressOrderByTimestampDesc(String ipAddress);
    
    /**
     * Find audit logs after a certain time
     */
    List<AuditLog> findByTimestampAfterOrderByTimestampDesc(Instant timestamp);
    
    /**
     * Find failed operations
     */
    @Query("SELECT a FROM AuditLog a WHERE a.success = false ORDER BY a.timestamp DESC")
    List<AuditLog> findFailedOperations();
    
    /**
     * Find audit logs with pagination
     */
    Page<AuditLog> findAllByOrderByTimestampDesc(Pageable pageable);
    
    /**
     * Count events by type
     */
    long countByEventType(String eventType);
    
    /**
     * Count failed events
     */
    long countBySuccessFalse();
    
    /**
     * Find recent events by user
     */
    @Query("SELECT a FROM AuditLog a WHERE a.username = :username AND a.timestamp > :since ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentEventsByUser(@Param("username") String username, @Param("since") Instant since);
}

