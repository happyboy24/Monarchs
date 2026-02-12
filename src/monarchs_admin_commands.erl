-module(monarchs_admin_commands).
-export([
    handle_admin_command/2,
    is_admin/1
]).

-include("monarchs_server.hrl").
-include_lib("monarchs/include/types.hrl").

%% ============================================================================
%% ADMIN COMMAND HANDLERS
%% ============================================================================

%% Register as owner admin (only first admin)
handle_admin_command(<<"/registeradmin ", Args/binary>>, State) ->
    case binary:split(Args, <<" ">>) of
        [Username, Password] ->
            UsernameStr = binary_to_list(Username),
            PasswordStr = binary_to_list(Password),
            case monarchs_server:register_admin(UsernameStr, PasswordStr) of
                ok ->
                    {ok, "\n*** ADMIN REGISTRATION SUCCESSFUL ***\nYou are now the OWNER admin of this server!\n\nUse /login to access your admin account.\n\n"};
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"}
            end;
        _ ->
            {ok, "Usage: /registeradmin <username> <password>\nPassword must be at least 8 characters.\n\n"}
    end;

%% Admin help
handle_admin_command(<<"/adminhelp">>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Admin commands require admin login.\n\n"};
        true ->
            AdminHelp = [
                "\n========= ADMIN HELP =========\n",
                "Admin Commands:\n",
                "  /promote <user> <role>  - Promote user (moderator, admin)\n",
                "  /demote <user>          - Demote user to regular user\n",
                "  /ban <user> <reason>     - Ban a user from the server\n",
                "  /unban <user>           - Unban a user\n",
                "  /kick <user>            - Kick a user from the server\n",
                "  /userinfo <user>        - Get user information\n",
                "  /onlineusers            - List all online users\n",
                "  /bannedusers            - List all banned users\n",
                "  /broadcast <message>    - Broadcast message to all users\n",
                "  /stats                  - Show server statistics\n",
                "  /shutdown <reason>      - Shutdown server (owner only)\n",
                "\nRoles: user < moderator < admin < owner\n",
                "================================\n\n"
            ],
            {ok, lists:flatten(AdminHelp)}
    end;

%% Promote user
handle_admin_command(<<"/promote ", Args/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            case binary:split(Args, <<" ">>) of
                [Username, Role] ->
                    UsernameStr = binary_to_list(Username),
                    RoleStr = binary_to_list(Role),
                    case monarchs_server:promote(Token, UsernameStr, RoleStr) of
                        ok ->
                            {ok, "User promoted successfully.\n\n"};
                        {error, Reason} ->
                            {ok, "Error: " ++ Reason ++ "\n\n"}
                    end;
                _ ->
                    {ok, "Usage: /promote <username> <role>\nRoles: moderator, admin\n\n"}
            end
    end;

%% Demote user
handle_admin_command(<<"/demote ", Username/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            UsernameStr = binary_to_list(Username),
            case monarchs_server:demote(Token, UsernameStr) of
                ok ->
                    {ok, "User demoted to regular user.\n\n"};
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"}
            end
    end;

%% Ban user
handle_admin_command(<<"/ban ", Args/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            case binary:split(Args, <<" ">>) of
                [Username, Reason] ->
                    UsernameStr = binary_to_list(Username),
                    ReasonStr = binary_to_list(Reason),
                    case monarchs_server:ban(Token, UsernameStr, ReasonStr) of
                        ok ->
                            {ok, "User banned successfully.\n\n"};
                        {error, BanReason} ->
                            {ok, "Error: " ++ BanReason ++ "\n\n"}
                    end;
                _ ->
                    {ok, "Usage: /ban <username> <reason>\n\n"}
            end
    end;

%% Unban user
handle_admin_command(<<"/unban ", Username/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            UsernameStr = binary_to_list(Username),
            case monarchs_server:unban(Token, UsernameStr) of
                ok ->
                    {ok, "User unbanned successfully.\n\n"};
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"}
            end
    end;

%% Kick user
handle_admin_command(<<"/kick ", Username/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            UsernameStr = binary_to_list(Username),
            case monarchs_server:kick(Token, UsernameStr) of
                ok ->
                    {ok, "User kicked successfully.\n\n"};
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"}
            end
    end;

%% Get user info
handle_admin_command(<<"/userinfo ", Username/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            UsernameStr = binary_to_list(Username),
            case monarchs_server:get_user_info(UsernameStr) of
                {error, Reason} ->
                    {ok, "Error: " ++ Reason ++ "\n\n"};
                Info ->
                    Role = maps:get(role, Info),
                    Status = maps:get(status, Info),
                    Banned = maps:get(banned, Info),
                    Created = maps:get(created_at, Info),
                    LastLogin = maps:get(last_login, Info),
                    Formatted = io_lib:format(
                        "\nUser Info for ~s:\n"
                        "  Role: ~p\n"
                        "  Status: ~p\n"
                        "  Banned: ~p\n"
                        "  Created: ~p\n"
                        "  Last Login: ~p\n\n",
                        [UsernameStr, Role, Status, Banned, Created, LastLogin]
                    ),
                    {ok, Formatted}
            end
    end;

%% List online users
handle_admin_command(<<"/onlineusers">>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            Users = monarchs_server:get_online_users(),
            case Users of
                [] ->
                    {ok, "No users currently online.\n\n"};
                _ ->
                    Formatted = ["Online users:\n" | 
                        [io_lib:format("  - ~s\n", [U]) || U <- Users] ++ ["\n"]],
                    {ok, lists:flatten(Formatted)}
            end
    end;

%% List banned users
handle_admin_command(<<"/bannedusers">>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            Users = monarchs_server:get_banned_users(),
            case Users of
                [] ->
                    {ok, "No banned users.\n\n"};
                _ ->
                    Formatted = ["Banned users:\n" | 
                        [io_lib:format("  - ~s\n", [U]) || U <- Users] ++ ["\n"]],
                    {ok, lists:flatten(Formatted)}
            end
    end;

%% Broadcast message
handle_admin_command(<<"/broadcast ", Message/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            MessageStr = binary_to_list(Message),
            monarchs_server:broadcast(Token, MessageStr),
            {ok, "Message broadcasted to all users.\n\n"}
    end;

%% Server stats
handle_admin_command(<<"/stats">>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Admin login required.\n\n"};
        true ->
            Stats = monarchs_server:get_stats(),
            TotalUsers = maps:get(total_users, Stats),
            OnlineUsers = maps:get(online_users, Stats),
            TotalRooms = maps:get(total_rooms, Stats),
            TotalMessages = maps:get(total_messages, Stats),
            Uptime = maps:get(uptime_seconds, Stats),
            Formatted = io_lib:format(
                "\n========== SERVER STATS ==========\n"
                "Total Users: ~p\n"
                "Online Users: ~p\n"
                "Total Rooms: ~p\n"
                "Total Messages: ~p\n"
                "Uptime: ~p seconds\n"
                "====================================\n\n",
                [TotalUsers, OnlineUsers, TotalRooms, TotalMessages, Uptime]
            ),
            {ok, Formatted}
    end;

%% Shutdown server
handle_admin_command(<<"/shutdown ", Reason/binary>>, State = #state{token = Token}) ->
    case is_admin(Token) of
        false ->
            {ok, "Permission denied. Owner login required.\n\n"};
        true ->
            ReasonStr = binary_to_list(Reason),
            case monarchs_server:shutdown(Token, ReasonStr) of
                ok ->
                    {ok, "Server shutdown initiated...\n\n"};
                {error, ShutdownReason} ->
                    {ok, "Error: " ++ ShutdownReason ++ "\n\n"}
            end
    end;

%% Unknown admin command
handle_admin_command(_Command, _State) ->
    {ok, "Unknown admin command. Type /adminhelp for available commands.\n\n"}.

%% ============================================================================
%% HELPER FUNCTIONS
%% ============================================================================

%% Check if user is admin
is_admin(undefined) -> false;
is_admin(Token) ->
    case ets:lookup(monarchs_sessions, Token) of
        [] -> false;
        [{_, Session}] ->
            Username = Session#session.username,
            case ets:lookup(monarchs_users, Username) of
                [] -> false;
                [{_, User}] ->
                    User#user.role =:= admin orelse User#user.role =:= owner
            end
    end.

