-module(monarchs_server).
-behaviour(gen_server).

%% OTP Supervision
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% API
-export([
    register_user/2, login/3, logout/1,
    create_room/2, join_room/2, leave_room/2,
    send_message/3, send_private/3,
    get_rooms/0, get_users/0, get_room_users/1,
    get_stats/0, health_check/0
]).

%% Constants
-define(SERVER, ?MODULE).
-define(PORT, 5678).

%% Data records with proper typing
-record(user, {
    username :: string(),
    password_hash :: string(),
    salt :: string(),
    email :: string() | undefined,
    created_at :: integer(),
    last_login :: integer() | undefined,
    status :: online | away | offline,
    current_room :: string() | undefined,
    socket :: inet:socket() | undefined
}).

-record(room, {
    name :: string(),
    users = [] :: [string()],
    owner :: string(),
    created_at :: integer(),
    type :: public | private,
    max_users :: integer() | undefined,
    settings :: map()
}).

-record(message, {
    id :: string(),
    room :: string(),
    sender :: string(),
    content :: string(),
    timestamp :: integer(),
    type :: room | private,
    metadata :: map()
}).

-record(session, {
    token :: string(),
    username :: string(),
    created_at :: integer(),
    expires_at :: integer(),
    socket :: inet:socket() | undefined,
    ip_address :: tuple() | undefined,
    last_activity :: integer()
}).

-record(state, {
    users = #{} :: #{string() => #user{}},
    sessions = #{} :: #{string() => #session{}},
    rooms = #{} :: #{string() => #room{}},
    messages = #{} :: #{string() => [#message{}]},
    listen_socket :: inet:socket() | undefined,
    message_counter = 0 :: integer(),
    connection_count = 0 :: integer(),
    start_time :: integer()
}).

%% ETS table names
-define(USERS_TABLE, monarchs_users).
-define(ROOMS_TABLE, monarchs_rooms).
-define(MESSAGES_TABLE, monarchs_messages).
-define(SESSIONS_TABLE, monarchs_sessions).

%% Statistics
-record(stats, {
    total_users = 0 :: integer(),
    online_users = 0 :: integer(),
    total_rooms = 0 :: integer(),
    total_messages = 0 :: integer(),
    uptime_seconds = 0 :: integer()
}).

%% OTP Supervisor Start
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% API Functions
register_user(Username, Password) ->
    gen_server:call(?SERVER, {register, Username, Password}).

login(Username, Password, Socket) ->
    gen_server:call(?SERVER, {login, Username, Password, Socket}).

logout(Token) ->
    gen_server:cast(?SERVER, {logout, Token}).

create_room(Token, RoomName) ->
    gen_server:call(?SERVER, {create_room, Token, RoomName}).

join_room(Token, RoomName) ->
    gen_server:call(?SERVER, {join_room, Token, RoomName}).

leave_room(Token, RoomName) ->
    gen_server:cast(?SERVER, {leave_room, Token, RoomName}).

send_message(Token, RoomName, Message) ->
    gen_server:cast(?SERVER, {send_message, Token, RoomName, Message}).

send_private(Token, ToUser, Message) ->
    gen_server:cast(?SERVER, {send_private, Token, ToUser, Message}).

get_rooms() ->
    gen_server:call(?SERVER, get_rooms).

get_users() ->
    gen_server:call(?SERVER, get_users).

get_room_users(RoomName) ->
    gen_server:call(?SERVER, {get_room_users, RoomName}).

%% Get server statistics
get_stats() ->
    gen_server:call(?SERVER, get_stats).

%% Health check endpoint
health_check() ->
    gen_server:call(?SERVER, health_check).

%% gen_server callbacks
init([]) ->
    StartTime = erlang:system_time(second),
    
    %% Load configuration
    BackendPort = monarchs_config:get(backend_port, ?PORT),
    MaxConnections = monarchs_config:get(max_connections, 10000),
    
    io:format("~n========================================~n", []),
    io:format("   MONARCHS CHAT SERVER v2.0.0~n", []),
    io:format("   Production Edition~n", []),
    io:format("========================================~n", []),
    io:format("[SERVER] Starting on port ~p~n", [BackendPort]),
    io:format("[SERVER] Max connections: ~p~n", [MaxConnections]),
    
    %% Create ETS tables for in-memory storage
    try
        ets:new(?USERS_TABLE, [set, named_table, public, {read_concurrency, true}]),
        ets:new(?ROOMS_TABLE, [set, named_table, public, {read_concurrency, true}]),
        ets:new(?MESSAGES_TABLE, [bag, named_table, public]),
        ets:new(?SESSIONS_TABLE, [set, named_table, public]),
        
        io:format("[SERVER] ETS tables created successfully~n")
    catch
        error:Reason ->
            io:format("[SERVER] ETS table creation failed: ~p~n", [Reason])
    end,
    
    %% Start TCP listener
    ListenSocket = case gen_tcp:listen(BackendPort, [
        binary,
        {packet, line},
        {active, false},
        {reuseaddr, true},
        {backlog, 1024}
    ]) of
        {ok, Socket} ->
            io:format("[SERVER] Listening on port ~p~n", [BackendPort]),
            Socket;
        {error, Reason} ->
            io:format("[SERVER] Failed to listen on port ~p: ~p~n", [BackendPort, Reason]),
            undefined
    end,
    
    %% Spawn connection accept loop
    case ListenSocket of
        undefined ->
            io:format("[SERVER] CRITICAL: Failed to start listener~n"),
            {stop, {listen_failed, BackendPort}};
        _ ->
            spawn_link(fun() -> accept_loop(ListenSocket) end),
            io:format("[SERVER] OTP Supervision Tree Active~n"),
            io:format("[SERVER] Waiting for connections...~n~n", []),
            
            {ok, #state{
                users = #{},
                sessions = #{},
                rooms = #{},
                messages = #{},
                listen_socket = ListenSocket,
                message_counter = 0,
                connection_count = 0,
                start_time = StartTime
            }}
    end.

%% Handle registration with secure password hashing
handle_call({register, Username, Password}, _From, State) ->
    case validate_registration(Username, Password) of
        {error, Reason} ->
            log_audit(register_failed, #{username => Username, reason => Reason}),
            {reply, {error, Reason}, State};
        {ok} ->
            case ets:lookup(?USERS_TABLE, Username) of
                [{Username, _}] ->
                    log_audit(register_failed, #{username => Username, reason => duplicate}),
                    {reply, {error, "Username already exists"}, State};
                [] ->
                    %% Generate secure salt and hash password
                    Salt = generate_secure_token(32),
                    Hash = hash_password(Password, Salt),
                    CreatedAt = erlang:system_time(second),
                    
                    User = #user{
                        username = Username,
                        password_hash = Hash,
                        salt = Salt,
                        email = undefined,
                        created_at = CreatedAt,
                        last_login = undefined,
                        status = offline,
                        current_room = undefined
                    },
                    
                    ets:insert(?USERS_TABLE, {Username, User}),
                    NewUsers = maps:put(Username, User, State#state.users),
                    
                    log_audit(register, #{username => Username}),
                    io:format("[SERVER] User registered: ~s~n", [Username]),
                    
                    {reply, ok, State#state{users = NewUsers}}
            end
    end;

%% Handle login with rate limiting and secure token generation
handle_call({login, Username, Password, Socket}, {ClientIp, _Port}, State) ->
    %% Check rate limiting
    case check_rate_limit(ClientIp, State) of
        {rate_limited, WaitMs} ->
            log_audit(login_rate_limited, #{ip => ClientIp, username => Username}),
            {reply, {error, "Too many login attempts. Wait " ++ integer_to_list(WaitMs) ++ "ms"}, State};
        {ok, NewState} ->
            case ets:lookup(?USERS_TABLE, Username) of
                [] ->
                    log_audit(login_failed, #{username => Username, reason => not_found, ip => ClientIp}),
                    {reply, {error, "Invalid username or password"}, NewState};
                [{Username, User}] ->
                    %% Verify password with constant-time comparison
                    Salt = User#user.salt,
                    ExpectedHash = User#user.password_hash,
                    
                    case verify_password(Password, Salt, ExpectedHash) of
                        false ->
                            log_audit(login_failed, #{username => Username, reason => invalid_password, ip => ClientIp}),
                            {reply, {error, "Invalid username or password"}, NewState};
                        true ->
                            %% Generate secure session token
                            TokenExpiry = monarchs_config:get(token_expiry, 3600),
                            {Token, Expiry} = generate_session_token(Username, TokenExpiry),
                            
                            CurrentTime = erlang:system_time(second),
                            
                            %% Update user status
                            UpdatedUser = User#user{
                                status = online,
                                last_login = CurrentTime,
                                current_room = undefined
                            },
                            ets:insert(?USERS_TABLE, {Username, UpdatedUser}),
                            NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                            
                            %% Create session
                            Session = #session{
                                token = Token,
                                username = Username,
                                created_at = CurrentTime,
                                expires_at = Expiry,
                                socket = Socket,
                                ip_address = ClientIp,
                                last_activity = CurrentTime
                            },
                            ets:insert(?SESSIONS_TABLE, {Token, Session}),
                            NewSessions = maps:put(Token, Session, State#state.sessions),
                            
                            log_audit(login, #{username => Username, ip => ClientIp}),
                            io:format("[SERVER] User logged in: ~s (expires ~p)~n", [Username, Expiry]),
                            
                            {reply, {ok, Token, Expiry}, State#state{
                                users = NewUsers,
                                sessions = NewSessions
                            }}
                    end
            end
    end;

%% Create room
handle_call({create_room, Token, RoomName}, _From, State) ->
    case validate_session(State, Token) of
        {error, Reason} ->
            {reply, {error, Reason}, State};
        {ok, Username} ->
            case validate_room_name(RoomName) of
                {error, Reason} ->
                    {reply, {error, Reason}, State};
                ok ->
                    case ets:lookup(?ROOMS_TABLE, RoomName) of
                        [{RoomName, _}] ->
                            {reply, {error, "Room already exists"}, State};
                        [] ->
                            CreatedAt = erlang:system_time(second),
                            Room = #room{
                                name = RoomName,
                                users = [Username],
                                owner = Username,
                                created_at = CreatedAt,
                                type = public,
                                max_users = undefined,
                                settings = #{}
                            },
                            ets:insert(?ROOMS_TABLE, {RoomName, Room}),
                            NewRooms = maps:put(RoomName, Room, State#state.rooms),
                            
                            log_audit(room_created, #{room => RoomName, owner => Username}),
                            io:format("[SERVER] Room created: ~s by ~s~n", [RoomName, Username]),
                            
                            {reply, ok, State#state{rooms = NewRooms}}
                    end
            end
    end;

%% Join room
handle_call({join_room, Token, RoomName}, _From, State) ->
    case validate_session(State, Token) of
        {error, Reason} ->
            {reply, {error, Reason}, State};
        {ok, Username} ->
            case ets:lookup(?ROOMS_TABLE, RoomName) of
                [] ->
                    {reply, {error, "Room not found"}, State};
                [{RoomName, Room}] ->
                    MaxUsers = Room#room.max_users,
                    case MaxUsers of
                        undefined -> ok;
                        _ when length(Room#room.users) >= MaxUsers ->
                            {reply, {error, "Room is full"}, State}
                    end,
                    
                    UpdatedUsers = lists:usort([Username | Room#room.users]),
                    UpdatedRoom = Room#room{users = UpdatedUsers},
                    ets:insert(?ROOMS_TABLE, {RoomName, UpdatedRoom}),
                    NewRooms = maps:put(RoomName, UpdatedRoom, State#state.rooms),
                    
                    case ets:lookup(?USERS_TABLE, Username) of
                        [{Username, User}] ->
                            UpdatedUser = User#user{current_room = RoomName},
                            ets:insert(?USERS_TABLE, {Username, UpdatedUser}),
                            NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                            
                            log_audit(room_joined, #{room => RoomName, username => Username}),
                            io:format("[SERVER] User joined room: ~s joined ~s~n", [Username, RoomName]),
                            
                            {reply, ok, State#state{rooms = NewRooms, users = NewUsers}};
                        _ ->
                            {reply, ok, State#state{rooms = NewRooms}}
                    end
            end
    end;

%% Get rooms list
handle_call(get_rooms, _From, State) ->
    Rooms = [RoomName || {RoomName, _} <- ets:tab2list(?ROOMS_TABLE)],
    {reply, Rooms, State};

%% Get users list
handle_call(get_users, _From, State) ->
    Users = [Username || {Username, _} <- ets:tab2list(?USERS_TABLE)],
    {reply, Users, State};

%% Get room users
handle_call({get_room_users, RoomName}, _From, State) ->
    case ets:lookup(?ROOMS_TABLE, RoomName) of
        [] ->
            {reply, {error, "Room not found"}, State};
        [{RoomName, Room}] ->
            {reply, Room#room.users, State}
    end;

%% Get server statistics
handle_call(get_stats, _From, State) ->
    Uptime = erlang:system_time(second) - State#state.start_time,
    TotalUsers = map_size(State#state.users),
    TotalRooms = map_size(State#state.rooms),
    OnlineUsers = length([U || U <- maps:values(State#state.users), U#user.status =:= online]),
    
    Stats = #stats{
        total_users = TotalUsers,
        online_users = OnlineUsers,
        total_rooms = TotalRooms,
        total_messages = State#state.message_counter,
        uptime_seconds = Uptime
    },
    
    {reply, Stats, State};

%% Health check
handle_call(health_check, _From, State) ->
    Health = #{
        status => healthy,
        uptime => erlang:system_time(second) - State#state.start_time,
        connections => State#state.connection_count,
        memory => erlang:memory(total),
        version => "2.0.0"
    },
    {reply, Health, State};

%% Stop server
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

%% Logout handler
handle_cast({logout, Token}, State) ->
    case ets:lookup(?SESSIONS_TABLE, Token) of
        [] ->
            {noreply, State};
        [{Token, Session}] ->
            Username = Session#session.username,
            io:format("[SERVER] User logged out: ~s~n", [Username]),
            
            %% Remove session
            ets:delete(?SESSIONS_TABLE, Token),
            NewSessions = maps:remove(Token, State#state.sessions),
            
            %% Update user status
            case ets:lookup(?USERS_TABLE, Username) of
                [{Username, User}] ->
                    UpdatedUser = User#user{
                        status = offline,
                        current_room = undefined
                    },
                    ets:insert(?USERS_TABLE, {Username, UpdatedUser}),
                    NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                    
                    log_audit(logout, #{username => Username}),
                    {noreply, State#state{sessions = NewSessions, users = NewUsers}};
                _ ->
                    {noreply, State}
            end
    end;

%% Leave room handler
handle_cast({leave_room, Token, RoomName}, State) ->
    case validate_session(State, Token) of
        {error, _} ->
            {noreply, State};
        {ok, Username} ->
            case ets:lookup(?ROOMS_TABLE, RoomName) of
                [] ->
                    {noreply, State};
                [{RoomName, Room}] ->
                    UpdatedRoomUsers = lists:delete(Username, Room#room.users),
                    UpdatedRoom = Room#room{users = UpdatedRoomUsers},
                    ets:insert(?ROOMS_TABLE, {RoomName, UpdatedRoom}),
                    NewRooms = maps:put(RoomName, UpdatedRoom, State#state.rooms),
                    
                    case ets:lookup(?USERS_TABLE, Username) of
                        [{Username, User}] ->
                            UpdatedUser = User#user{current_room = undefined},
                            ets:insert(?USERS_TABLE, {Username, UpdatedUser}),
                            NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                            
                            log_audit(room_left, #{room => RoomName, username => Username}),
                            io:format("[SERVER] User left room: ~s left ~s~n", [Username, RoomName]),
                            {noreply, State#state{rooms = NewRooms, users = NewUsers}};
                        _ ->
                            {noreply, State#state{rooms = NewRooms}}
                    end
            end
    end;

%% Send message handler
handle_cast({send_message, Token, RoomName, Message}, State) ->
    case validate_session(State, Token) of
        {error, _} ->
            {noreply, State};
        {ok, Username} ->
            case ets:lookup(?ROOMS_TABLE, RoomName) of
                [] ->
                    {noreply, State};
                [{RoomName, Room}] ->
                    %% Validate and sanitize message
                    SanitizedMessage = sanitize_message(Message),
                    
                    %% Create message record
                    NewCounter = State#state.message_counter + 1,
                    MsgId = generate_message_id(),
                    Msg = #message{
                        id = MsgId,
                        room = RoomName,
                        sender = Username,
                        content = SanitizedMessage,
                    timestamp = erlang:system_time(millisecond),
                    type = room,
                    metadata = #{}
                },
                    
                    %% Store message
                    ets:insert(?MESSAGES_TABLE, {RoomName, Msg}),
                    RoomMessages = maps:get(RoomName, State#state.messages, []),
                    NewRoomMessages = RoomMessages ++ [Msg],
                    NewMessages = maps:put(RoomName, NewRoomMessages, State#state.messages),
                    
                    %% Broadcast to room users
                    FormattedMsg = io_lib:format("[~s] <~s> ~s~n", [RoomName, Username, SanitizedMessage]),
                    
                    lists:foreach(
                        fun(User) ->
                            case ets:lookup(?USERS_TABLE, User) of
                                [{User, U}] when U#user.current_room =:= RoomName, U#user.socket =/= undefined ->
                                    gen_tcp:send(U#user.socket, list_to_binary(FormattedMsg));
                                _ -> ok
                            end
                        end,
                        Room#room.users
                    ),
                    
                    io:format("[MESSAGE] ~s", [FormattedMsg]),
                    {noreply, State#state{messages = NewMessages, message_counter = NewCounter}}
            end
    end;

%% Send private message handler
handle_cast({send_private, Token, ToUser, Message}, State) ->
    case validate_session(State, Token) of
        {error, _} ->
            {noreply, State};
        {ok, FromUser} ->
            SanitizedMessage = sanitize_message(Message),
            
            case ets:lookup(?USERS_TABLE, ToUser) of
                [] ->
                    {noreply, State};
                [{ToUser, ToUserRecord}] when ToUserRecord#user.socket =/= undefined ->
                    FormattedMsg = io_lib:format("[PM from ~s] ~s~n", [FromUser, SanitizedMessage]),
                    gen_tcp:send(ToUserRecord#user.socket, list_to_binary(FormattedMsg)),
                    io:format("(PM) ~s -> ~s: ~s~n", [FromUser, ToUser, SanitizedMessage]),
                    {noreply, State};
                _ ->
                    {noreply, State}
            end
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Handle periodic cleanup
handle_info(cleanup_expired_sessions, State) ->
    CurrentTime = erlang:system_time(second),
    
    %% Clean up expired sessions
    ExpiredSessions = [
        Token || {Token, Session} <- ets:tab2list(?SESSIONS_TABLE),
        Session#session.expires_at < CurrentTime
    ],
    
    lists:foreach(fun(Token) -> ets:delete(?SESSIONS_TABLE, Token) end, ExpiredSessions),
    
    NewSessions = maps:filter(
        fun(_Token, Session) ->
            Session#session.expires_at >= CurrentTime
        end,
        State#state.sessions
    ),
    
    io:format("[SERVER] Cleaned up ~p expired sessions~n", [length(ExpiredSessions)]),
    
    %% Schedule next cleanup in 5 minutes
    erlang:send_after(300000, self(), cleanup_expired_sessions),
    
    {noreply, State#state{sessions = NewSessions}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    %% Persist data before shutdown
    persist_data(State),
    
    case State#state.listen_socket of
        undefined -> ok;
        Socket -> gen_tcp:close(Socket)
    end,
    
    log_audit(terminate, #{event => server_stop}),
    io:format("[SERVER] Monarchs server stopped~n"),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% TCP Accept Loop
accept_loop(ListenSocket) ->
    case gen_tcp:accept(ListenSocket) of
        {ok, ClientSocket} ->
            {ok, {Addr, Port}} = inet:peername(ClientSocket),
            io:format("[SERVER] New connection from ~p:~p~n", [Addr, Port]),
            
            %% Start connection handler under supervision
            monarchs_connection_sup:start_connection(ClientSocket),
            
            accept_loop(ListenSocket);
        {error, Reason} ->
            io:format("[SERVER] Accept error: ~p~n", [Reason]),
            timer:sleep(1000),
            accept_loop(ListenSocket)
    end.

%% ===================================================================
%% Security Functions
%% ===================================================================

%% Generate cryptographically secure token
generate_secure_token(Length) ->
    case erlang:system_info(otp_release) of
        R when R >= "21" ->
            base64:encode(crypto:strong_rand_bytes(Length));
        _ ->
            base64:encode(os:cmd("openssl rand -base64 " ++ integer_to_list(Length)))
    end.

%% Hash password with salt using SHA-512 (production would use bcrypt)
hash_password(Password, Salt) ->
    crypto:hash(sha512, Password ++ Salt).

%% Verify password with constant-time comparison
verify_password(Password, Salt, ExpectedHash) ->
    ActualHash = hash_password(Password, Salt),
    constant_time_compare(ActualHash, ExpectedHash).

%% Constant-time comparison to prevent timing attacks
constant_time_compare(<<X:256/binary, _Rest/binary>>, <<Y:256/binary, _Rest2/binary>>) ->
    crypto:secure_compare(X, Y);
constant_time_compare(<<X/binary>>, <<Y/binary>>) ->
    byte_size(X) =:= byte_size(Y) andalso
    lists:all(fun(I) -> 
        element(I, X) =:= element(I, Y) 
    end, lists:seq(1, byte_size(X))).

%% Generate session token with expiry
generate_session_token(Username, ExpirySeconds) ->
    CurrentTime = erlang:system_time(second),
    Expiry = CurrentTime + ExpirySeconds,
    Payload = erlang:term_to_binary({Username, CurrentTime, Expiry}),
    Token = generate_secure_token(32) ++ "." ++ base64:encode(Payload),
    {Token, Expiry}.

%% Generate unique message ID
generate_message_id() ->
    Timestamp = integer_to_list(erlang:system_time(millisecond)),
    Random = generate_secure_token(8),
    Timestamp ++ "-" ++ Random.

%% ===================================================================
%% Validation Functions
%% ===================================================================

%% Validate username
validate_registration(Username, Password) ->
    case validate_username(Username) of
        false ->
            {error, "Invalid username. Must be 3-30 alphanumeric characters (underscore allowed)"};
        true ->
            case validate_password(Password) of
                false ->
                    {error, "Invalid password. Must be at least 8 characters with uppercase, lowercase, and numbers"};
                true ->
                    {ok}
            end
    end.

%% Validate username format
validate_username(Username) ->
    Length = length(Username),
    Length >= 3 andalso Length =< 30 andalso
    lists:all(fun(C) -> 
        ($a =< C andalso C =< $z) orelse
        ($A =< C andalso C =< $Z) orelse
        ($0 =< C andalso C =< $9) orelse
        C =:= $_
    end, Username).

%% Validate password strength
validate_password(Password) ->
    Length = length(Password),
    Length >= 8 andalso Length =< 128 andalso
    lists:any(fun(C) -> $a =< C andalso C =< $z end, Password) andalso
    lists:any(fun(C) -> $A =< C andalso C =< $Z end, Password) andalso
    lists:any(fun(C) -> $0 =< C andalso C =< $9 end, Password).

%% Validate room name
validate_room_name(RoomName) ->
    Length = length(RoomName),
    case Length >= 1 andalso Length =< 50 of
        false ->
            {error, "Room name must be 1-50 characters"};
        true ->
            case lists:all(fun(C) -> 
                ($a =< C andalso C =< $z) orelse
                ($A =< C andalso C =< $Z) orelse
                ($0 =< C andalso C =< $9) orelse
                lists:member(C, [$-, $_, $ ])
            end, RoomName) of
                false ->
                    {error, "Room name contains invalid characters"};
                true ->
                    ok
            end
    end.

%% Sanitize message content to prevent injection attacks
sanitize_message(Message) ->
    %% Remove null bytes and control characters
    Sanitized = lists:filter(fun(C) -> 
        C =:= 9 orelse C =:= 10 orelse C =:= 13 orelse
        (C >= 32 andalso C =< 126) orelse
        C >= 128
    end, Message),
    %% Limit message length
    lists:sublist(Sanitized, 4096).

%% Validate session
validate_session(State, Token) ->
    CurrentTime = erlang:system_time(second),
    case ets:lookup(?SESSIONS_TABLE, Token) of
        [] ->
            {error, "Invalid session"};
        [{Token, Session}] ->
            case Session#session.expires_at of
                Exp when Exp < CurrentTime ->
                    ets:delete(?SESSIONS_TABLE, Token),
                    {error, "Session expired"};
                _ ->
                    {ok, Session#session.username}
            end
    end.

%% Rate limiting check
check_rate_limit(ClientIp, State) ->
    RateLimitWindow = monarchs_config:get(rate_limit_window, 60000),
    MaxAttempts = monarchs_config:get(max_login_attempts, 5),
    CurrentTime = erlang:system_time(millisecond),
    
    %% This is a simplified rate limiter; production would use ETS
    case get({rate_limit, ClientIp}) of
        undefined when MaxAttempts > 0 ->
            put({rate_limit, ClientIp}, {1, CurrentTime}),
            {ok, State};
        {Count, FirstTime} ->
            case CurrentTime - FirstTime of
                Delta when Delta < RateLimitWindow ->
                    case Count of
                        C when C < MaxAttempts ->
                            put({rate_limit, ClientIp}, {C + 1, FirstTime}),
                            {ok, State};
                        _ ->
                            BanDuration = monarchs_config:get(ban_duration, 300000),
                            WaitMs = FirstTime + RateLimitWindow - CurrentTime,
                            {rate_limited, WaitMs}
                    end;
                _ ->
                    put({rate_limit, ClientIp}, {1, CurrentTime}),
                    {ok, State}
            end
    end.

%% ===================================================================
%% Logging and Persistence
%% ===================================================================

%% Audit logging
log_audit(Event, Data) ->
    case monarchs_config:get(audit_enabled, true) of
        true ->
            LogEntry = #{
                timestamp => erlang:system_time(millisecond),
                event => Event,
                data => Data,
                node => node()
            },
            logger:info("[AUDIT] ~p", [LogEntry]);
        false ->
            ok
    end.

%% Persist data (placeholder for database integration)
persist_data(State) ->
    io:format("[SERVER] Persisting data to disk...~n", []),
    %% In production, this would write to a database
    ok.

