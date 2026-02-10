-module(monarchs_room_sup).
-behaviour(supervisor).

%% API
-export([start_link/0, start_room/1, start_room/2]).

%% Supervisor callbacks
-export([init/1]).

%% Constants
-define(MAX_RESTARTS, 10).
-define(TIME_WINDOW, 60). %% 60 seconds

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Start a room process with just name
start_room(RoomName) ->
    start_room(RoomName, #{}).

%% Start a room process with options
start_room(RoomName, Options) ->
    ChildSpec = #{
        id => RoomName,
        start => {monarchs_room, start_link, [RoomName, Options]},
        restart => transient,
        shutdown => 5000,
        type => worker,
        modules => [monarchs_room]
    },
    supervisor:start_child(?MODULE, ChildSpec).

init([]) ->
    io:format("[ROOM_SUP] Room supervisor initialized~n"),
    io:format("[ROOM_SUP] Strategy: simple_one_for_one, MaxRestarts: ~p, Window: ~ps~n",
              [?MAX_RESTARTS, ?TIME_WINDOW]),
    
    {ok, {{simple_one_for_one, ?MAX_RESTARTS, ?TIME_WINDOW}, []}}.

