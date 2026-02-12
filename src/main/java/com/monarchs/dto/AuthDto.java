package com.monarchs.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Data Transfer Objects for authentication operations.
 */
public class AuthDto {
    
    /**
     * Request DTO for user registration
     */
    public static class RegisterRequest {
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
        private String username;
        
        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        private String password;
        
        @Size(max = 255, message = "Email must not exceed 255 characters")
        private String email;
        
        // Admin registration with secret
        private String adminSecret;
        
        // Default constructor
        public RegisterRequest() {}
        
        public RegisterRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }
        
        // Getters and Setters
        public String getUsername() {
            return username;
        }
        
        public void setUsername(String username) {
            this.username = username;
        }
        
        public String getPassword() {
            return password;
        }
        
        public void setPassword(String password) {
            this.password = password;
        }
        
        public String getEmail() {
            return email;
        }
        
        public void setEmail(String email) {
            this.email = email;
        }
        
        public String getAdminSecret() {
            return adminSecret;
        }
        
        public void setAdminSecret(String adminSecret) {
            this.adminSecret = adminSecret;
        }
    }
    
    /**
     * Request DTO for user login
     */
    public static class LoginRequest {
        @NotBlank(message = "Username is required")
        private String username;
        
        @NotBlank(message = "Password is required")
        private String password;
        
        // Optional: remember me flag
        private boolean rememberMe;
        
        // Default constructor
        public LoginRequest() {}
        
        public LoginRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }
        
        // Getters and Setters
        public String getUsername() {
            return username;
        }
        
        public void setUsername(String username) {
            this.username = username;
        }
        
        public String getPassword() {
            return password;
        }
        
        public void setPassword(String password) {
            this.password = password;
        }
        
        public boolean isRememberMe() {
            return rememberMe;
        }
        
        public void setRememberMe(boolean rememberMe) {
            this.rememberMe = rememberMe;
        }
    }
    
    /**
     * Response DTO for successful authentication
     */
    public static class AuthResponse {
        private String token;
        private String tokenType = "Bearer";
        private long expiresIn;
        private String username;
        private String role;
        private UserDto user;
        
        // Default constructor
        public AuthResponse() {}
        
        public AuthResponse(String token, long expiresIn, String username, String role) {
            this.token = token;
            this.expiresIn = expiresIn;
            this.username = username;
            this.role = role;
        }
        
        // Getters and Setters
        public String getToken() {
            return token;
        }
        
        public void setToken(String token) {
            this.token = token;
        }
        
        public String getTokenType() {
            return tokenType;
        }
        
        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }
        
        public long getExpiresIn() {
            return expiresIn;
        }
        
        public void setExpiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
        }
        
        public String getUsername() {
            return username;
        }
        
        public void setUsername(String username) {
            this.username = username;
        }
        
        public String getRole() {
            return role;
        }
        
        public void setRole(String role) {
            this.role = role;
        }
        
        public UserDto getUser() {
            return user;
        }
        
        public void setUser(UserDto user) {
            this.user = user;
        }
    }
    
    /**
     * Response DTO for logout
     */
    public static class LogoutResponse {
        private String message = "Successfully logged out";
        
        public LogoutResponse() {}
        
        public LogoutResponse(String message) {
            this.message = message;
        }
        
        public String getMessage() {
            return message;
        }
        
        public void setMessage(String message) {
            this.message = message;
        }
    }
}

