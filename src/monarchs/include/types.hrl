%% Monarchs Chat System Types

%% Basic types
-type username() :: string().
-type password_hash() :: string().
-type salt() :: string().
-type email() :: string() | undefined.
-type timestamp() :: integer().
-type room_name() :: string().
-type message_content() :: string().
-type token() :: string().
-type ip_address() :: tuple().

%% Enums
-type user_status() :: online | away | offline.
-type user_role() :: user | moderator | admin | owner.
-type room_type() :: public | private.
-type message_type() :: room | private.

%% Records (forward declarations for types)
-type user() :: #user{}.
-type room() :: #room{}.
-type message() :: #message{}.
-type session() :: #session{}.
-type state() :: #state{}.
-type stats() :: #stats{}.