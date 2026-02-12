-module(monarchs_connection).
-behaviour(gen_server).

%% API
-export([start_link/1, start_link/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Constants
-define(TCP_OPTIONS, [
    binary,
    {packet, line},
    {active, false},
    {reuseaddr, true},
    {nodelay, true}
]).

-record(state, {
    socket :: inet:socket() | undefined,
    peer_address :: tuple() | undefined,
    server_pid :: pid() | undefined,
    username :: string() | undefined,
    token :: string() | undefined,
    current_room :: string() | undefined,
    recv_buffer = <<>> :: binary(),
    connected_at :: integer() | undefined,
    last_activity :: integer() | undefined
}).

start_link(Socket) ->
    start_link(Socket, #{}).

start_link(Socket, Options) ->
    gen_server:start_link(?MODULE, {Socket, Options}, []).

init({Socket, _Options}) ->
    erlang:process_flag(priority, high),
    
    {ok, {Addr, Port}} = inet:peername(Socket),
    ConnectedAt = erlang:system_time(second),
    
    io:format("[CONNECTION] New TCP connection from ~p:~p~n", [Addr, Port]),
    
    send_welcome(Socket),
    
    {ok, #state{
        socket = Socket,
        peer_address = {Addr, Port},
        server_pid = undefined,
        username = undefined,
        token = undefined,
        current_room = undefined,
        recv_buffer = <<>>,
        connected_at = ConnectedAt,
        last_activity = ConnectedAt
    }, 60000}.

handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({tcp, Socket, Data}, State = #state{socket = Socket}) ->
    LastActivity = erlang:system_time(second),
    NewBuffer = <<(State#state.recv_buffer)/binary, Data/binary>>,
    
    case process_data(Socket, NewBuffer, State) of
        {ok, RemainingBuffer, NewState} ->
            {noreply, NewState#state{recv_buffer = RemainingBuffer, last_activity = LastActivity}, 60000};
        {error, Reason, NewState} ->
            io:format("[CONNECTION] Processing error: ~p~n", [Reason]),
            {stop, {error, Reason}, NewState}
    end;

handle_info({tcp_closed, Socket}, State = #state{socket = Socket}) ->
    io:format("[CONNECTION] TCP connection closed~n"),
    {stop, normal, State};

handle_info({tcp_error, Socket, Reason}, State = #state{socket = Socket}) ->
    io:format("[CONNECTION] TCP error: ~p~n", [Reason]),
    {stop, {tcp_error, Reason}, State};

handle_info(timeout, State) ->
    io:format("[CONNECTION] Connection timeout (inactive)~n"),
    {stop, timeout, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    case State#state.socket of
        undefined -> ok;
        Socket ->
            gen_tcp:close(Socket)
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Process incoming data line by line
process_data(Socket, Buffer, State) ->
    case binary:split(Buffer, <<"\n">>) of
        [Line, Rest] ->
            CleanLine = binary:trim(Line, trailing, <<"\r">>),
            case handle_command(CleanLine, State) of
                {ok, Response} when is_binary(Response) ->
                    gen_tcp:send(Socket, Response),
                    process_data(Socket, Rest, State);
                {ok, Response} when is_list(Response) ->
                    gen_tcp:send(Socket, list_to_binary(Response)),
                    process_data(Socket, Rest, State);
                {ok, stop} ->
                    {ok, <<>>, State};
                {error, Reason} ->
                    {error, Reason, State}
            end;
        [_Incomplete] ->
            {ok, Buffer, State}
    end.

%% Handle client commands
handle_command(<<"/register ", Args/binary>>, State) ->
    case binary:split(Args, <<" ">>) of
        [Username, Password] ->
            UsernameStr = binary_to_list(Username),
            PasswordStr = binary_to_list(Password),
            case monarchs_server:register_user(UsernameStr, PasswordStr) of
                ok ->
                    {ok, "Registration successful! You can now login with /login <username> <password>\n\n"};
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"}
            end;
        _ ->
            {ok, "Usage: /register <username> <password>\nPassword must be at least 8 characters.\n\n"}
    end;

handle_command(<<"/login ", Args/binary>>, State = #state{socket = Socket}) ->
    case binary:split(Args, <<" ">>) of
        [Username, Password] ->
            UsernameStr = binary_to_list(Username),
            PasswordStr = binary_to_list(Password),
            case monarchs_server:login(UsernameStr, PasswordStr, Socket) of
                {ok, Token, Expiry} ->
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
                    {ok, lists:flatten(Menu)};
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"}
            end;
        _ ->
            {ok, "Usage: /login <username> <password>\n\n"}
    end;

handle_command(<<"/rooms">>, State) ->
    Rooms = monarchs_server:get_rooms(),
    case Rooms of
        [] ->
            {ok, "No rooms available. Create one with /create <name>\n\n"};
        _ ->
            Formatted = ["Available rooms:\n" | 
                [io_lib:format("  - ~s\n", [R]) || R <- Rooms] ++ ["\n"]],
            {ok, lists:flatten(Formatted)}
    end;

handle_command(<<"/create ", RoomName/binary>>, State = #state{token = undefined}) ->
    {ok, "Please login first with /login <username> <password>\n\n"};
handle_command(<<"/create ", RoomName/binary>>, State = #state{token = Token}) ->
    RoomNameStr = binary_to_list(RoomName),
    case monarchs_server:create_room(Token, RoomNameStr) of
        ok ->
            {ok, "Room '" ++ RoomNameStr ++ "' created! Join with /join " ++ RoomNameStr ++ "\n\n"};
        {error, Reason} ->
            {ok, "Error: " ++ Reason ++ "\n\n"}
    end;

handle_command(<<"/join ", RoomName/binary>>, State = #state{token = undefined}) ->
    {ok, "Please login first with /login <username> <password>\n\n"};
handle_command(<<"/join ", RoomName/binary>>, State = #state{token = Token}) ->
    RoomNameStr = binary_to_list(RoomName),
    case monarchs_server:join_room(Token, RoomNameStr) of
        ok ->
            {ok, "Joined room '" ++ RoomNameStr ++ "'! Start typing to chat!\n\n"};
        {error, Reason} ->
            {ok, "Error: " ++ Reason ++ "\n\n"}
    end;

handle_command(<<"/leave">>, State = #state{token = undefined}) ->
    {ok, "Please login first\n\n"};
handle_command(<<"/leave">>, State = #state{token = Token, current_room = undefined}) ->
    {ok, "You are not in a room\n\n"};
handle_command(<<"/leave">>, State = #state{token = Token, current_room = RoomName}) ->
    case monarchs_server:leave_room(Token, RoomName) of
        ok ->
            {ok, "Left room '" ++ RoomName ++ "'\n\n"};
        {error, Reason} ->
            {ok, "Error: " ++ Reason ++ "\n\n"}
    end;

handle_command(<<"/users">>, State) ->
    Users = monarchs_server:get_users(),
    Formatted = io_lib:format("Registered users: ~p\n\n", [Users]),
    {ok, Formatted};

handle_command(<<"/msg ", Args/binary>>, State = #state{token = undefined}) ->
    {ok, "Please login first\n\n"};
handle_command(<<"/msg ", Args/binary>>, State = #state{token = Token}) ->
    case binary:split(Args, <<" ">>) of
        [ToUser, Message] ->
            ToUserStr = binary_to_list(ToUser),
            MessageStr = binary_to_list(Message),
            monarchs_server:send_private(Token, ToUserStr, MessageStr),
            {ok, "PM sent to " ++ ToUserStr ++ "\n\n"};
        _ ->
            {ok, "Usage: /msg <username> <message>\n\n"}
    end;

handle_command(<<"/logout">>, State = #state{token = undefined}) ->
    {ok, "Not logged in\n\n"};
handle_command(<<"/logout">>, State = #state{token = Token}) ->
    monarchs_server:logout(Token),
    {ok, "Logged out successfully\n\n"};

handle_command(<<"/help">>, State) ->
    HelpMsg = [
        "\n========= HELP =========\n",
        "Commands:\n",
        "  /register <user> <pass> - Register a new account\n",
        "  /login <user> <pass>    - Login to your account\n",
        "  /rooms                  - List all available rooms\n",
        "  /create <room_name>    - Create a new room\n",
        "  /join <room_name>      - Join a room\n",
        "  /leave                 - Leave current room\n",
        "  /users                 - List registered users\n",
        "  /msg <user> <msg>      - Send private message\n",
        "  /logout                - Logout\n",
        "  /quit                  - Disconnect\n",
        "\nJust type to send messages to the current room!\n",
        "=========================\n\n"
    ],
    {ok, lists:flatten(HelpMsg)};

handle_command(<<"/quit">>, State) ->
    io:format("[CONNECTION] Client requested disconnect~n"),
    {ok, "Goodbye!\n"},
    gen_tcp:close(State#state.socket),
    {ok, stop};

handle_command(<<>>, _State) ->
    {ok, "> "};

handle_command(<<$/, _/binary>>, _State) ->
    {ok, "Unknown command. Type /help for available commands\n\n"};

handle_command(Message, State = #state{token = undefined}) ->
    {ok, "Please login first. Type /help for available commands\n\n"};
handle_command(Message, State = #state{token = Token, current_room = undefined}) ->
    {ok, "Join a room first with /join <room_name>\n\n"};
handle_command(Message, State = #state{token = Token, current_room = RoomName}) ->
    monarchs_server:send_message(Token, RoomName, binary_to_list(Message)),
    {ok, "> "}.

%% Send welcome message
send_welcome(Socket) ->
    WelcomeMsg = [
        "~n========================================\n",
        "        WELCOME TO MONARCHS CHAT\n",
        "      Production-Ready Edition v2.0\n",
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
        "Security: Passwords are hashed. Sessions use JWT tokens.\n",
        "Rate Limiting: Max 5 login attempts per minute.\n\n",
        "========================================\n\n",
        "Enter command: "
    ],
    gen_tcp:send(Socket, list_to_binary(lists:flatten(WelcomeMsg))).

