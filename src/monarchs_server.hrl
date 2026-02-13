%% Monarchs Chat Server Records and Types

%% User record
-record(user, {
    username,
    password_hash,
    salt,
    email,
    created_at,
    last_login,
    status,
    current_room,
    socket,
    role,
    banned,
    ban_reason,
    ban_expires
}).

%% Room record
-record(room, {
    name,
    users = [],
    owner,
    created_at,
    type,
    max_users,
    settings
}).

%% Message record
-record(message, {
    id,
    room,
    sender,
    content,
    timestamp,
    type,
    metadata
}).

%% Session record
-record(session, {
    token,
    username,
    created_at,
    expires_at,
    socket,
    ip_address,
    last_activity
}).

%% Server state record
-record(server_state, {
    users = #{},
    sessions = #{},
    rooms = #{},
    messages = #{},
    listen_socket,
    message_counter = 0,
    connection_count = 0,
    start_time
}).

%% Statistics record
-record(stats, {
    total_users = 0,
    online_users = 0,
    total_rooms = 0,
    total_messages = 0,
    uptime = 0,
    memory_usage = 0
}).

%% ETS table names
-define(USERS_TABLE, monarchs_users).
-define(ROOMS_TABLE, monarchs_rooms).
-define(MESSAGES_TABLE, monarchs_messages).
-define(SESSIONS_TABLE, monarchs_sessions).
-define(BANNED_TABLE, monarchs_banned).

%% Admin secret for initial setup (change in production!)
-define(ADMIN_SECRET, "monarchs_admin_secret_2024").