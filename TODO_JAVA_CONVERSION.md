# Monarchs Erlang to Java Conversion - Task List

## Overview
Convert the Monarchs Chat System from Erlang to Java using Spring Boot 3.2

## Phase 1: Domain Models
- [ ] Create Role enum (user, moderator, admin, owner)
- [ ] Create User entity with JPA annotations
- [ ] Create Room entity with JPA annotations
- [ ] Create Message entity with JPA annotations
- [ ] Create Session entity with JPA annotations
- [ ] Create DTO classes (UserDTO, RoomDTO, MessageDTO, AuthDTO)

## Phase 2: Configuration & Properties
- [ ] Update pom.xml with all required dependencies
- [ ] Create application.yml with all config settings
- [ ] Create AppConfig class for custom configuration
- [ ] Create ConfigurationProperties classes for YAML mapping
- [ ] Implement environment variable overrides

## Phase 3: Repositories (Spring Data JPA)
- [ ] Create UserRepository interface
- [ ] Create RoomRepository interface
- [ ] Create MessageRepository interface
- [ ] Create SessionRepository interface
- [ ] Create BannedUserRepository interface

## Phase 4: Security Layer
- [ ] Implement JwtTokenProvider for JWT token generation/validation
- [ ] Implement JwtAuthenticationFilter
- [ ] Create SecurityConfig with Spring Security
- [ ] Implement PasswordEncoder with BCrypt
- [ ] Create CustomUserDetailsService

## Phase 5: Services
- [ ] Implement UserService (CRUD operations)
- [ ] Implement AuthService (login/register with rate limiting)
- [ ] Implement RoomService (create/join/leave rooms)
- [ ] Implement MessageService (send/receive messages)
- [ ] Implement SessionService (session management)
- [ ] Implement AdminService (ban, kick, promote, demote)
- [ ] Implement StatsService (server statistics)
- [ ] Implement RateLimiterService

## Phase 6: WebSocket Support
- [ ] Create WebSocketConfig
- [ ] Implement ChatWebSocketHandler
- [ ] Create WebSocket message DTOs
- [ ] Implement presence tracking
- [ ] Add heartbeat mechanism

## Phase 7: REST Controllers
- [ ] Create AuthController (login, register, logout)
- [ ] Create RoomController (CRUD operations)
- [ ] Create MessageController (send/get messages)
- [ ] Create AdminController (admin operations)
- [ ] Create StatsController (health, statistics)
- [ ] Create UserController (user profile, settings)

## Phase 8: Exception Handling
- [ ] Create custom exceptions (UserNotFoundException, RoomNotFoundException, etc.)
- [ ] Implement GlobalExceptionHandler
- [ ] Add proper error responses

## Phase 9: Auditing & Logging
- [ ] Implement AuditLog entity
- [ ] Create AuditService
- [ ] Add AOP logging for key operations

## Phase 10: Testing
- [ ] Write unit tests for services
- [ ] Write integration tests for controllers
- [ ] Add test configuration

## Phase 11: Documentation
- [ ] Update README.md with Java version documentation
- [ ] Create API documentation (OpenAPI/Swagger)
- [ ] Add sample configuration files

## Completion Criteria
- [ ] All Erlang functionality ported to Java
- [ ] Build succeeds with Maven
- [ ] Application starts and runs correctly
- [ ] All tests pass
- [ ] Documentation updated

