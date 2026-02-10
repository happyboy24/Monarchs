# Monarchs Chat System - Complete Architecture Model

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Web Browser (SPA)                       │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │  │
│  │  │ Auth Module │ │ Chat Module │ │ UI/UX Components   │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │ WebSocket
┌────────────────────────────┴────────────────────────────────────┐
│                     RELAY LAYER (Node.js)                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              WebSocket Server (ws)                          │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │  │
│  │  │ Connection  │ │ Message     │ │ Session            │  │  │
│  │  │ Manager     │ │ Router      │ │ Manager            │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │ TCP
┌────────────────────────────┴────────────────────────────────────┐
│                   CORE LAYER (Erlang/OTP)                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Application Layer                             │  │
│  │  ┌─────────────────────────────────────────────────────┐│  │
│  │  │              monarchs_app (Application)              ││  │
│  │  └─────────────────────────────────────────────────────┘│  │
│  └───────────────────────────────────────────────────────────┘  │
│                              ▲                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              monarchs_sup (Supervisor)                    │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │  │
│  │  │ User Sup   │ │ Room Sup    │ │ Connection Sup     │  │  │
│  │  │ (simple_   │ │ (simple_    │ │ (simple_one_      │  │  │
│  │   one_for_    │ │  one_for_    │ │  for_one, 100)    │  │  │
│  │   one, 5)     │ │   one, 10)  │ │                   │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              monarchs_server (gen_server)                   │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │  │
│  │  │ User        │ │ Room        │ │ Message            │  │  │
│  │  │ Registry    │ │ Manager     │ │ Handler           │  │  │
│  │  │ (ETS)       │ │ (ETS)       │ │ (ETS + Broadcast) │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘  │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │  │
│  │  │ Session     │ │ Presence    │ │ Persistence        │  │  │
│  │  │ Manager     │ │ Tracker     │ │ Layer             │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                    DATA LAYER (ETS Tables)                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │  │
│  │  │ monarchs_   │ │ monarchs_   │ │ monarchs_          │ │  │
│  │  │ users       │ │ rooms       │ │ messages           │ │  │
│  │  │ (set,       │ │ (set,       │ │ (bag,              │ │  │
│  │   public)      │ │  public)     │ │  public)           │ │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## OTP Supervision Tree

```
monarchs_app
    │
    └── monarchs_sup (one_for_one, intensity=10, period=60)
            │
            ├── monarchs_user_sup (simple_one_for_one, max_restarts=5)
            │       │
            │       └── monarchs_user (dynamic workers)
            │
            ├── monarchs_room_sup (simple_one_for_one, max_restarts=10)
            │       │
            │       └── monarchs_room (dynamic workers)
            │
            ├── monarchs_connection_sup (simple_one_for_one, max_restarts=100)
            │       │
            │       └── monarchs_connection (TCP connection handlers)
            │
            └── monarchs_server (gen_server, permanent)
                    │
                    └── TCP Listener (gen_tcp:listen)
                            │
                            └── accept_loop
```

## Module Specifications

### 1. monarchs_app.erl
- Main application callback module
- Starts the supervision tree on application:start(monarchs)

### 2. monarchs_sup.erl  
- Root supervisor
- One-for-one restart strategy
- Intensity: 10 restarts per 60 seconds
- Spawns all child supervisors

### 3. monarchs_user_sup.erl
- User process supervisor
- Simple one-for-one strategy
- Max 5 restarts per 60 seconds
- Dynamically spawns user processes

### 4. monarchs_room_sup.erl
- Room process supervisor  
- Simple one-for-one strategy
- Max 10 restarts per 60 seconds
- Dynamically spawns room processes

### 5. monarchs_connection_sup.erl
- TCP connection supervisor
- Simple one-for-one strategy
- Max 100 restarts per 60 seconds
- High limit for concurrent connections

### 6. monarchs_server.erl
- Main gen_server process
- User registration and login
- Room management
- Message routing and broadcasting
- ETS table management
- TCP listener spawning

## ETS Tables

### monarchs_users (set, public)
- Key: Username
- Value: #user record
- Stores: username, password, socket, current_room, status, last_seen

### monarchs_rooms (set, public)
- Key: RoomName  
- Value: #room record
- Stores: name, users list, owner, created_at, type

### monarchs_messages (bag, public)
- Key: RoomName
- Value: #message record
- Stores: id, room, sender, content, timestamp, type

## Message Flow

### User Registration
```
Client → WebSocket → Relay → TCP → monarchs_server
         ← ack ←        ← ack ←
```

### Join Room & Send Message
```
1. Client → /join room
2. Server adds user to room
3. Client types message
4. Server broadcasts to all room users
5. All clients receive message
```

### Private Message
```
1. Client → /msg user message
2. Server looks up recipient socket
3. Server sends PM to recipient
4. Both parties see the message
```

## Fault Tolerance

- **User process crashes** → User supervisor restarts (5 attempts)
- **Room process crashes** → Room supervisor restarts (10 attempts)  
- **Connection crashes** → Connection supervisor restarts (100 attempts)
- **Server crashes** → Application supervisor restarts entire tree

## Scalability

- Each room is isolated (message broadcast only to room members)
- ETS provides O(1) lookups for users and rooms
- Supervision tree allows parallel processing
- Connection pooling via supervisor limits

