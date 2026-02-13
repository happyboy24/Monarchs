%% Monarchs Chat Records for Connection Module

%% User record
-record(user, {
    username :: string(),
    password_hash :: string(),
    salt :: string(),
    email :: string() | undefined,
    created_at :: integer(),
    last_login :: integer() | undefined,
    status :: online | away | offline,
    current_room :: string() | undefined,
    socket :: inet:socket() | undefined,
    role :: user | moderator | admin | owner,
    banned :: boolean(),
    ban_reason :: string() | undefined,
    ban_expires :: integer() | undefined
}).

%% Session record
-record(session, {
    token :: string(),
    username :: string(),
    created_at :: integer(),
    expires_at :: integer(),
    socket :: inet:socket() | undefined,
    ip_address :: tuple() | undefined,
    last_activity :: integer()
}).