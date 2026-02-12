package com.monarchs.repository;

import com.monarchs.model.Room;
import com.monarchs.model.RoomType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Room entity operations.
 */
@Repository
public interface RoomRepository extends JpaRepository<Room, Long> {
    
    /**
     * Find room by name
     */
    Optional<Room> findByName(String name);
    
    /**
     * Check if room name exists
     */
    boolean existsByName(String name);
    
    /**
     * Find all rooms by type
     */
    List<Room> findByType(RoomType type);
    
    /**
     * Find all active rooms
     */
    List<Room> findByActiveTrue();
    
    /**
     * Find active rooms by type
     */
    List<Room> findByTypeAndActiveTrue(RoomType type);
    
    /**
     * Find rooms by owner username
     */
    @Query("SELECT r FROM Room r JOIN r.owner o WHERE o.username = :username")
    List<Room> findByOwnerUsername(@Param("username") String username);
    
    /**
     * Find rooms containing a user
     */
    @Query("SELECT r FROM Room r WHERE :username MEMBER OF r.users AND r.active = true")
    List<Room> findRoomsContainingUser(@Param("username") String username);
    
    /**
     * Find public rooms
     */
    @Query("SELECT r FROM Room r WHERE r.type = 'PUBLIC' AND r.active = true ORDER BY r.createdAt DESC")
    List<Room> findPublicRooms();
    
    /**
     * Count active rooms
     */
    long countByActiveTrue();
    
    /**
     * Search rooms by name (case-insensitive)
     */
    @Query("SELECT r FROM Room r WHERE LOWER(r.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) AND r.active = true")
    List<Room> searchByName(@Param("searchTerm") String searchTerm);
}

