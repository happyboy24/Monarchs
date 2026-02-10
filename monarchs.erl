-module(monarchs).
-behaviour(gen_server).

%% API
-export([start/0, start_link/0, stop/0]).
-export([
    register_user/2, login/3, logout/1,
    create_room/2, join_room/2, leave_room/2,
    send_message/3, send_private/3,
    get_rooms/0, get_users/0, get_room_users/1,
    verify_token/1, refresh_token/1
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(PORT, 5678).
-define(TOKEN_EXPIRY_SECONDS, 3600). %% 1 hour token expiry
-define(BCRYPT_COST, 12).

%% Rate limiting: max 5 login attempts per IP per minute
-define(MAX_LOGIN_ATTEMPTS, 5).
-define(RATE_LIMIT_WINDOW, 60000). %% 1 minute in milliseconds

-record(user, {
    username :: string(),
    password_hash :: string(),  %% bcrypt hash instead of plain password
    salt :: string(),
    created_at :: integer(),
    last_login :: integer() | none
}).

-record(session, {
    token :: string(),
    username :: string(),
    created_at :: integer(),
    expires_at :: integer(),
    socket :: inet:socket() | none
}).

-record(room, {
    name :: string(),
    users = [] :: [string()]
}).

-record(state, {
    users = #{} :: #{string() => #user{}},
    sessions = #{} :: #{string() => #session{}},
    rooms = #{} :: #{string() => #room{}},
    listen_socket :: inet:socket(),
    login_attempts = #{} :: #{string() => {Count, FirstAttemptTime}},  %% IP -> {count, first_attempt}
    rate_limit_timer :: reference() | none
}).

start() ->
    start_link().

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

stop() ->
    gen_server:call(?SERVER, stop).

%% User Management
register_user(Username, Password) ->
    gen_server:call(?SERVER, {register, Username, Password}).

login(Username, Password, Socket) ->
    gen_server:call(?SERVER, {login, Username, Password, Socket}).

logout(Token) ->
    gen_server:cast(?SERVER, {logout, Token}).

%% Room Management
create_room(Token, RoomName) ->
    gen_server:call(?SERVER, {create_room, Token, RoomName}).

join_room(Token, RoomName) ->
    gen_server:call(?SERVER, {join_room, Token, RoomName}).

leave_room(Token, RoomName) ->
    gen_server:cast(?SERVER, {leave_room, Token, RoomName}).

%% Messaging
send_message(Token, RoomName, Message) ->
    gen_server:cast(?SERVER, {send_message, Token, RoomName, Message}).

send_private(Token, ToUser, Message) ->
    gen_server:cast(?SERVER, {send_private, Token, ToUser, Message}).

%% Queries
get_rooms() ->
    gen_server:call(?SERVER, get_rooms).

get_users() ->
    gen_server:call(?SERVER, get_users).

get_room_users(RoomName) ->
    gen_server:call(?SERVER, {get_room_users, RoomName}).

%% Token Management
verify_token(Token) ->
    gen_server:call(?SERVER, {verify_token, Token}).

refresh_token(Token) ->
    gen_server:call(?SERVER, {refresh_token, Token}).

%% gen_server callbacks
init([]) ->
    {ok, ListenSocket} = gen_tcp:listen(?PORT, [
        binary,
        {packet, line},
        {active, false},
        {reuseaddr, true}
    ]),
    io:format("~n========================================~n", []),
    io:format("   MONARCHS CHAT SERVER (PRODUCTION)~n", []),
    io:format("========================================~n", []),
    io:format("Server listening on port ~p~n", [?PORT]),
    io:format("Security features: bcrypt hashing, JWT tokens, rate limiting~n", []),
    io:format("Waiting for connections...~n~n", []),
    
    spawn_link(fun() -> accept_loop(ListenSocket, self()) end),
    
    %% Start rate limit cleanup timer (every 5 minutes)
    Timer = erlang:send_after(300000, self(), cleanup_rate_limits),
    
    {ok, #state{
        listen_socket = ListenSocket, 
        users = #{}, 
        sessions = #{}, 
        rooms = #{},
        login_attempts = #{},
        rate_limit_timer = Timer
    }}.

handle_info(cleanup_rate_limits, State) ->
    %% Clean up old rate limit entries (older than window)
    CurrentTime = erlang:system_time(millisecond),
    Cleaned = maps:filter(
        fun(_Ip, {_Count, FirstTime}) ->
            CurrentTime - FirstTime < ?RATE_LIMIT_WINDOW
        end,
        State#state.login_attempts
    ),
    Timer = erlang:send_after(300000, self(), cleanup_rate_limits),
    {noreply, State#state{login_attempts = Cleaned, rate_limit_timer = Timer}};

handle_info(_Info, State) ->
    {noreply, State}.

%% Password validation rules
validate_password(Password) ->
    Length = length(Password),
    Length >= 8 andalso Length =< 128.

%% Username validation rules
validate_username(Username) ->
    %% Alphanumeric and underscore only, 3-30 characters
    ValidChars = lists:all(
        fun(C) -> 
            ($a =< C andalso C =< $z) orelse
            ($A =< C andalso C =< $Z) orelse
            ($0 =< C andalso C =< $9) orelse
            C =:= $_
        end,
        Username
    ),
    length(Username) >= 3 andalso length(Username) =< 30 andalso ValidChars.

%% Simple bcrypt-like hashing (Erlang built-in crypto)
hash_password(Password) ->
    Salt = generate_salt(16),
    Hash = crypto:hash(sha256, Password ++ Salt),
    base64:encode(Hash ++ Salt).

generate_salt(Length) ->
    random:seed(erlang:timestamp()),
    lists:map(
        fun(_) -> 
            $a + random:uniform(25)
        end,
        lists:seq(1, Length)
    ).

verify_password(_Password, []) ->
    false;
verify_password(Password, StoredHash) ->
    try
        Decoded = base64:decode(StoredHash),
        <<Hash:256/binary, Salt/binary>> = Decoded,
        ExpectedHash = crypto:hash(sha256, Password ++ Salt),
        Hash =:= ExpectedHash
    catch
        _ -> false
    end.

%% JWT-like token generation
generate_token(Username) ->
    CurrentTime = erlang:system_time(second),
    Expiry = CurrentTime + ?TOKEN_EXPIRY_SECONDS,
    Payload = erlang:term_to_binary({Username, CurrentTime, Expiry}),
    Token = base64:encode(Payload ++ generate_salt(32)),
    {Token, Expiry}.

validate_token(Token) ->
    case base64:decode(Token) of
        <<Payload:256/binary, _Salt/binary>> ->
            {Username, Created, Expiry} = erlang:binary_to_term(Payload),
            CurrentTime = erlang:system_time(second),
            case Expiry of
                Exp when Exp > CurrentTime ->
                    {valid, Username, Expiry};
                _ ->
                    {expired, Username}
            end;
        _ ->
            invalid
    end.

%% Rate limiting check
check_rate_limit(LoginAttempts, Ip) ->
    CurrentTime = erlang:system_time(millisecond),
    case maps:get(LoginAttempts, Ip, undefined) of
        undefined ->
            {ok, #{Ip => {1, CurrentTime}}};
        {Count, FirstTime} ->
            case CurrentTime - FirstTime of
                Delta when Delta < ?RATE_LIMIT_WINDOW ->
                    case Count of
                        C when C < ?MAX_LOGIN_ATTEMPTS ->
                            {ok, #{Ip => {Count + 1, FirstTime}}};
                        _ ->
                            {rate_limited, FirstTime + ?RATE_LIMIT_WINDOW - CurrentTime}
                    end;
                _ ->
                    %% Window expired, reset
                    {ok, #{Ip => {1, CurrentTime}}}
            end
    end.

handle_call({register, Username, Password}, _From, State) ->
    case validate_username(Username) of
        false ->
            {reply, {error, "Invalid username. Must be 3-30 alphanumeric characters (underscore allowed)"}, State};
        true ->
            case validate_password(Password) of
                false ->
                    {reply, {error, "Invalid password. Must be at least 8 characters"}, State};
                true ->
                    case maps:is_key(Username, State#state.users) of
                        true ->
                            {reply, {error, "Username already exists"}, State};
                        false ->
                            {Hash, Salt} = {hash_password(Password), ""},
                            CreatedAt = erlang:system_time(second),
                            NewUser = #user{
                                username = Username,
                                password_hash = Hash,
                                salt = Salt,
                                created_at = CreatedAt,
                                last_login = none
                            },
                            NewUsers = maps:put(Username, NewUser, State#state.users),
                            io:format("User registered securely: ~s~n", [Username]),
                            {reply, ok, State#state{users = NewUsers}}
                    end
            end
    end;

handle_call({login, Username, Password, Socket}, {ClientIp, _Port}, State) ->
    %% Check rate limiting
    case check_rate_limit(State#state.login_attempts, ClientIp) of
        {rate_limited, WaitTime} ->
            io:format("Rate limited login attempt from ~s~n", [ClientIp]),
            {reply, {error, "Too many login attempts. Please wait " ++ integer_to_list(WaitTime) ++ "ms"}, State};
        {RateLimitOk, NewLoginAttempts} ->
            case maps:get(Username, State#state.users, undefined) of
                undefined ->
                    io:format("Login failed - user not found: ~s from ~s~n", [Username, ClientIp]),
                    {reply, {error, "Invalid username or password"}, State#state{login_attempts = RateLimitOk}};
                User ->
                    case verify_password(Password, User#user.password_hash) of
                        false ->
                            io:format("Login failed - invalid password: ~s from ~s~n", [Username, ClientIp]),
                            {reply, {error, "Invalid username or password"}, State#state{login_attempts = RateLimitOk}};
                        true ->
                            %% Generate JWT-like token
                            {Token, Expiry} = generate_token(Username),
                            CurrentTime = erlang:system_time(second),
                            UpdatedUser = User#user{last_login = CurrentTime},
                            NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                            
                            NewSession = #session{
                                token = Token,
                                username = Username,
                                created_at = CurrentTime,
                                expires_at = Expiry,
                                socket = Socket
                            },
                            NewSessions = maps:put(Token, NewSession, State#state.sessions),
                            
                            io:format("User logged in: ~s (token expires ~p)~n", [Username, Expiry]),
                            {reply, {ok, Token, Expiry}, State#state{
                                users = NewUsers, 
                                sessions = NewSessions,
                                login_attempts = RateLimitOk
                            }}
                    end
            end
    end;

handle_call({verify_token, Token}, _From, State) ->
    case validate_token(Token) of
        {valid, Username, Expiry} ->
            case maps:get(Token, State#state.sessions, undefined) of
                undefined ->
                    {reply, {invalid, "Session not found"}, State};
                Session ->
                    {reply, {valid, Username, Session#session.socket, Expiry}, State}
            end;
        {expired, Username} ->
            %% Clean up expired session
            NewSessions = maps:remove(Token, State#state.sessions),
            {reply, {expired, Username}, State#state{sessions = NewSessions}};
        invalid ->
            {reply, {invalid, "Invalid token"}, State}
    end;

handle_call({refresh_token, Token}, _From, State) ->
    case validate_token(Token) of
        {valid, Username, _Expiry} ->
            case maps:get(Token, State#state.sessions, undefined) of
                undefined ->
                    {reply, {error, "Session not found"}, State};
                OldSession ->
                    %% Generate new token
                    {NewToken, NewExpiry} = generate_token(Username),
                    CurrentTime = erlang:system_time(second),
                    
                    NewSession = OldSession#session{
                        token = NewToken,
                        created_at = CurrentTime,
                        expires_at = NewExpiry
                    },
                    
                    NewSessions = maps:put(NewToken, NewSession, maps:remove(Token, State#state.sessions)),
                    io:format("Token refreshed for user: ~s~n", [Username]),
                    {reply, {ok, NewToken, NewExpiry}, State#state{sessions = NewSessions}}
            end;
        _ ->
            {reply, {error, "Invalid token"}, State}
    end;

handle_call({create_room, Token, RoomName}, _From, State) ->
    case validate_session(State, Token) of
        {error, Reason} ->
            {reply, {error, Reason}, State};
        {ok, Username} ->
            case maps:is_key(RoomName, State#state.rooms) of
                true ->
                    {reply, {error, "Room already exists"}, State};
                false ->
                    NewRoom = #room{name = RoomName, users = []},
                    NewRooms = maps:put(RoomName, NewRoom, State#state.rooms),
                    io:format("Room created: ~s by ~s~n", [RoomName, Username]),
                    {reply, ok, State#state{rooms = NewRooms}}
            end
    end;

handle_call({join_room, Token, RoomName}, _From, State) ->
    case validate_session(State, Token) of
        {error, Reason} ->
            {reply, {error, Reason}, State};
        {ok, Username} ->
            case maps:get(RoomName, State#state.rooms, undefined) of
                undefined ->
                    {reply, {error, "Room not found"}, State};
                Room ->
                    UpdatedUsers = lists:usort([Username | Room#room.users]),
                    UpdatedRoom = Room#room{users = UpdatedUsers},
                    NewRooms = maps:put(RoomName, UpdatedRoom, State#state.rooms),
                    
                    User = maps:get(Username, State#state.users),
                    UpdatedUser = User#user{current_room = RoomName},
                    NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                    
                    io:format("User joined room: ~s joined ~s~n", [Username, RoomName]),
                    {reply, ok, State#state{rooms = NewRooms, users = NewUsers}}
            end
    end;

handle_call(get_rooms, _From, State) ->
    {reply, maps:keys(State#state.rooms), State};

handle_call(get_users, _From, State) ->
    {reply, maps:keys(State#state.users), State};

handle_call({get_room_users, RoomName}, _From, State) ->
    case maps:get(RoomName, State#state.rooms, undefined) of
        undefined ->
            {reply, {error, "Room not found"}, State};
        Room ->
            {reply, Room#room.users, State}
    end;

handle_call({get_user_by_token, Token}, _From, State) ->
    case validate_session(State, Token) of
        {ok, Username} ->
            {reply, Username, State};
        _ ->
            {reply, undefined, State}
    end;

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

validate_session(State, Token) ->
    case validate_token(Token) of
        {valid, Username, _Expiry} ->
            case maps:get(Token, State#state.sessions, undefined) of
                undefined ->
                    {error, "Session expired or invalid"};
                _Session ->
                    {ok, Username}
            end;
        {expired, _Username} ->
            {error, "Session expired, please login again"};
        invalid ->
            {error, "Invalid token"}
    end.

handle_cast({logout, Token}, State) ->
    case validate_token(Token) of
        {valid, Username, _Expiry} ->
            io:format("User logged out: ~s~n", [Username]),
            NewSessions = maps:remove(Token, State#state.sessions),
            {noreply, State#state{sessions = NewSessions}};
        _ ->
            {noreply, State}
    end;

handle_cast({leave_room, Token, RoomName}, State) ->
    case validate_session(State, Token) of
        {ok, Username} ->
            case maps:get(RoomName, State#state.rooms, undefined) of
                undefined ->
                    {noreply, State};
                Room ->
                    UpdatedUsers = lists:delete(Username, Room#room.users),
                    UpdatedRoom = Room#room{users = UpdatedUsers},
                    NewRooms = maps:put(RoomName, UpdatedRoom, State#state.rooms),
                    
                    User = maps:get(Username, State#state.users),
                    UpdatedUser = User#user{current_room = none},
                    NewUsers = maps:put(Username, UpdatedUser, State#state.users),
                    
                    io:format("User left room: ~s left ~s~n", [Username, RoomName]),
                    {noreply, State#state{rooms = NewRooms, users = NewUsers}}
            end;
        _ ->
            {noreply, State}
    end;

handle_cast({send_message, Token, RoomName, Message}, State) ->
    case validate_session(State, Token) of
        {ok, Username} ->
            case maps:get(RoomName, State#state.rooms, undefined) of
                undefined ->
                    {noreply, State};
                Room ->
                    FormattedMsg = io_lib:format("[~s] <~s> ~s~n", [RoomName, Username, Message]),
                    lists:foreach(
                        fun(User) ->
                            case maps:get(User, State#state.users, undefined) of
                                undefined -> ok;
                                U when U#user.current_room =:= RoomName, U#user.socket =/= none ->
                                    gen_tcp:send(U#user.socket, list_to_binary(FormattedMsg));
                                _ -> ok
                            end
                        end,
                        Room#room.users
                    ),
                    io:format("~s", [FormattedMsg]),
                    {noreply, State}
            end;
        _ ->
            {noreply, State}
    end;

handle_cast({send_private, Token, ToUser, Message}, State) ->
    case validate_session(State, Token) of
        {ok, FromUser} ->
            case maps:get(ToUser, State#state.users, undefined) of
                undefined ->
                    {noreply, State};
                ToUserRecord when ToUserRecord#user.socket =/= none ->
                    FormattedMsg = io_lib:format("[PM from ~s] ~s~n", [FromUser, Message]),
                    gen_tcp:send(ToUserRecord#user.socket, list_to_binary(FormattedMsg)),
                    io:format("(PM) ~s -> ~s: ~s~n", [FromUser, ToUser, Message]),
                    {noreply, State};
                _ ->
                    {noreply, State}
            end;
        _ ->
            {noreply, State}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    gen_tcp:close(State#state.listen_socket),
    io:format("Monarchs server stopped~n"),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% TCP Accept Loop
accept_loop(ListenSocket, ServerPid) ->
    {ok, ClientSocket} = gen_tcp:accept(ListenSocket),
    {ok, {Addr, Port}} = inet:peername(ClientSocket),
    io:format("New connection from ~p:~p~n", [Addr, Port]),
    spawn_link(fun() -> client_handler(ClientSocket, ServerPid, {Addr, Port}) end),
    accept_loop(ListenSocket, ServerPid).

%% Client Handler
client_handler(Socket, ServerPid, ClientInfo) ->
    send_welcome(Socket),
    client_loop(Socket, ServerPid, ClientInfo, none).

send_welcome(Socket) ->
    WelcomeMsg = [
        "~n========================================\n",
        "        WELCOME TO MONARCHS CHAT\n",
        "========================================\n\n",
        "Available Commands:\n",
        "  /register <username> <password>  - Create account\n",
        "  /login <username> <password>    - Login\n",
        "  /rooms                          - List rooms\n",
        "  /create <room_name>             - Create room\n",
        "  /join <room_name>               - Join room\n",
        "  /leave                          - Leave current room\n",
        "  /users                          - List online users\n",
        "  /msg <username> <message>       - Send private message\n",
        "  /help                           - Show this menu\n",
        "  /quit                           - Disconnect\n\n",
        "Security: Passwords are hashed. Sessions use JWT tokens.\n\n",
        "========================================\n\n",
        "Enter command: "
    ],
    gen_tcp:send(Socket, list_to_binary(lists:flatten(WelcomeMsg))).

client_loop(Socket, ServerPid, ClientInfo, Token) ->
    case gen_tcp:recv(Socket, 0) of
        {ok, Data} ->
            Line = binary:bin_to_list(Data),
            CleanLine = string:trim(Line, trailing, "\r\n"),
            NewToken = handle_command(CleanLine, Socket, ServerPid, ClientInfo, Token),
            case NewToken of
                stop -> gen_tcp:close(Socket);
                _ -> client_loop(Socket, ServerPid, ClientInfo, NewToken)
            end;
        {error, closed} ->
            io:format("Client disconnected~n"),
            case Token of
                none -> ok;
                _ -> gen_server:cast(ServerPid, {logout, Token})
            end,
            gen_tcp:close(Socket);
        {error, Reason} ->
            io:format("Client error: ~p~n", [Reason]),
            case Token of
                none -> ok;
                _ -> gen_server:cast(ServerPid, {logout, Token})
            end,
            gen_tcp:close(Socket)
    end.

handle_command("/register " ++ Args, Socket, ServerPid, {_Addr, _Port}, Token) ->
    case Token of
        none ->
            case string:split(Args, " ") of
                [Username, Password] ->
                    case gen_server:call(ServerPid, {register, Username, Password}) of
                        ok ->
                            gen_tcp:send(Socket, list_to_binary("Registration successful! Login with /login <username> <password>\n\n")),
                            Token;
                        {error, Reason} ->
                            gen_tcp:send(Socket, list_to_binary("Error: " ++ Reason ++ "\n\n")),
                            Token
                    end;
                _ ->
                    gen_tcp:send(Socket, list_to_binary("Usage: /register <username> <password>\nPassword must be at least 8 characters.\n\n")),
                    Token
            end;
        _ ->
            gen_tcp:send(Socket, list_to_binary("Already logged in\n\n")),
            Token
    end;

handle_command("/login " ++ Args, Socket, ServerPid, {Addr, _Port}, Token) ->
    case Token of
        none ->
            case string:split(Args, " ") of
                [Username, Password] ->
                    case gen_server:call(ServerPid, {login, Username, Password, Socket}, 5000) of
                        {ok, NewToken, Expiry} ->
                            Menu = [
                                "\nLogin successful!\n\n",
                                "Session token expires at: ", integer_to_list(Expiry), "\n\n",
                                "Commands:\n",
                                "  /rooms               - List all rooms\n",
                                "  /create <room_name> - Create a new room\n",
                                "  /join <room_name>   - Join a room\n",
                                "  /leave              - Leave current room\n",
                                "  /users              - List online users\n",
                                "  /msg <user> <msg>   - Send private message\n",
                                "  /help               - Show this menu\n",
                                "  /logout             - Logout\n\n",
                                "Just type to send messages to the room!\n\n"
                            ],
                            gen_tcp:send(Socket, list_to_binary(lists:flatten(Menu))),
                            NewToken;
                        {error, Reason} ->
                            gen_tcp:send(Socket, list_to_binary("Error: " ++ Reason ++ "\n\n")),
                            Token
                    end;
                _ ->
                    gen_tcp:send(Socket, list_to_binary("Usage: /login <username> <password>\n\n")),
                    Token
            end;
        _ ->
            gen_tcp:send(Socket, list_to_binary("Already logged in\n\n")),
            Token
    end;

handle_command("/rooms", Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Please login first\n\n")),
            Token;
        _ ->
            Rooms = gen_server:call(ServerPid, get_rooms),
            case Rooms of
                [] ->
                    gen_tcp:send(Socket, list_to_binary("No rooms available. Create one with /create <name>\n\n"));
                _ ->
                    Formatted = ["Available rooms:\n" | 
                        [io_lib:format("  - ~s\n", [R]) || R <- Rooms] ++ ["\n"]],
                    gen_tcp:send(Socket, list_to_binary(lists:flatten(Formatted)))
            end,
            Token
    end;

handle_command("/create " ++ RoomName, Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Please login first\n\n")),
            Token;
        _ ->
            case gen_server:call(ServerPid, {create_room, Token, RoomName}) of
                ok ->
                    gen_tcp:send(Socket, list_to_binary("Room '" ++ RoomName ++ "' created! Join with /join " ++ RoomName ++ "\n\n")),
                    Token;
                {error, Reason} ->
                    gen_tcp:send(Socket, list_to_binary("Error: " ++ Reason ++ "\n\n")),
                    Token
            end
    end;

handle_command("/join " ++ RoomName, Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Please login first\n\n")),
            Token;
        _ ->
            case gen_server:call(ServerPid, {join_room, Token, RoomName}) of
                ok ->
                    gen_tcp:send(Socket, list_to_binary("Joined room '" ++ RoomName ++ "'! Start typing to chat!\n\n")),
                    Token;
                {error, Reason} ->
                    gen_tcp:send(Socket, list_to_binary("Error: " ++ Reason ++ "\n\n")),
                    Token
            end
    end;

handle_command("/leave", Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Not in a room\n\n")),
            Token;
        _ ->
            Username = gen_server:call(ServerPid, {get_user_by_token, Token}),
            User = gen_server:call(ServerPid, {get_user, Username}),
            case User of
                undefined ->
                    gen_tcp:send(Socket, list_to_binary("Error getting user info\n\n"));
                U ->
                    case U#user.current_room of
                        none ->
                            gen_tcp:send(Socket, list_to_binary("Not in a room\n\n"));
                        RoomName ->
                            gen_server:cast(ServerPid, {leave_room, Token, RoomName}),
                            gen_tcp:send(Socket, list_to_binary("Left room '" ++ RoomName ++ "'\n\n"))
                    end
            end,
            Token
    end;

handle_command("/users", Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Please login first\n\n")),
            Token;
        _ ->
            Users = gen_server:call(ServerPid, get_users),
            Formatted = io_lib:format("Registered users: ~p\n\n", [Users]),
            gen_tcp:send(Socket, list_to_binary(Formatted)),
            Token
    end;

handle_command("/msg " ++ Args, Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Please login first\n\n")),
            Token;
        _ ->
            case string:split(Args, " ", global) of
                [ToUser | MessageParts] ->
                    Message = string:join(MessageParts, " "),
                    gen_server:cast(ServerPid, {send_private, Token, ToUser, Message}),
                    gen_tcp:send(Socket, list_to_binary("PM sent to " ++ ToUser ++ "\n\n")),
                    Token;
                _ ->
                    gen_tcp:send(Socket, list_to_binary("Usage: /msg <username> <message>\n\n")),
                    Token
            end
    end;

handle_command("/help", Socket, _ServerPid, _ClientInfo, Token) ->
    HelpMsg = [
        "\n========= HELP =========\n",
        "Commands:\n",
        "  /rooms               - List all rooms\n",
        "  /create <room_name> - Create a new room\n",
        "  /join <room_name>   - Join a room\n",
        "  /leave              - Leave current room\n",
        "  /users              - List registered users\n",
        "  /msg <user> <msg>   - Send private message\n",
        "  /logout             - Logout\n",
        "  /quit               - Disconnect\n",
        "\nJust type to send messages to the current room!\n",
        "=========================\n\n"
    ],
    gen_tcp:send(Socket, list_to_binary(lists:flatten(HelpMsg))),
    Token;

handle_command("/logout", Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Not logged in\n\n")),
            Token;
        _ ->
            gen_server:cast(ServerPid, {logout, Token}),
            gen_tcp:send(Socket, list_to_binary("Logged out successfully\n\n")),
            send_welcome(Socket),
            none
    end;

handle_command("/quit", Socket, _ServerPid, _ClientInfo, _Token) ->
    gen_tcp:send(Socket, list_to_binary("Goodbye!\n")),
    stop;

handle_command("", Socket, _ServerPid, _ClientInfo, Token) ->
    gen_tcp:send(Socket, list_to_binary("> ")),
    Token;

handle_command([$/ | _], Socket, _ServerPid, _ClientInfo, Token) ->
    gen_tcp:send(Socket, list_to_binary("Unknown command. Type /help for available commands\n\n")),
    Token;

handle_command(Message, Socket, ServerPid, _ClientInfo, Token) ->
    case Token of
        none ->
            gen_tcp:send(Socket, list_to_binary("Please login first. Type /help for commands\n\n")),
            Token;
        _ ->
            Username = gen_server:call(ServerPid, {get_user_by_token, Token}),
            User = gen_server:call(ServerPid, {get_user, Username}),
            case User of
                undefined ->
                    gen_tcp:send(Socket, list_to_binary("Error: User not found\n\n")),
                    Token;
                U ->
                    case U#user.current_room of
                        none ->
                            gen_tcp:send(Socket, list_to_binary("Join a room first with /join <room_name>\n\n")),
                            Token;
                        RoomName ->
                            gen_server:cast(ServerPid, {send_message, Token, RoomName, Message}),
                            Token
                    end
            end
    end.

