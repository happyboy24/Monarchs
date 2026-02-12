package com.monarchs.model;

/**
 * Room type enum representing the visibility of a chat room.
 */
public enum RoomType {
    /**
     * Public room - visible to all users and can be joined freely
     */
    PUBLIC,
    
    /**
     * Private room - requires invitation or owner approval to join
     */
    PRIVATE
}

