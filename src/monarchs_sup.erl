-module(monarchs_sup).
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Child names
-define(CONFIG_CHILD, monarchs_config).
-define(SERVER_CHILD, monarchs_server).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    io:format("[SUPERVISOR] Starting Monarchs supervision tree...~n", []),
    
    %% Configuration server (singleton, permanent)
    ConfigSpec = #{
        id => ?CONFIG_CHILD,
        start => {monarchs_config, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [monarchs_config]
    },
    
    %% Main server with one-for-one restart strategy
    ServerSpec = #{
        id => ?SERVER_CHILD,
        start => {monarchs_server, start_link, []},
        restart => permanent,
        shutdown => 10000,
        type => worker,
        modules => [monarchs_server]
    },
    
    %% User supervisor for dynamic user processes
    UserSupSpec = #{
        id => monarchs_user_sup,
        start => {monarchs_user_sup, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => supervisor,
        modules => [monarchs_user_sup]
    },
    
    %% Room supervisor for dynamic room processes
    RoomSupSpec = #{
        id => monarchs_room_sup,
        start => {monarchs_room_sup, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => supervisor,
        modules => [monarchs_room_sup]
    },
    
    %% Connection supervisor for TCP connection handlers
    ConnectionSupSpec = #{
        id => monarchs_connection_sup,
        start => {monarchs_connection_sup, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => supervisor,
        modules => [monarchs_connection_sup]
    },
    
    %% Supervision strategy
    Strategy = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },
    
    Children = [
        ConfigSpec,
        ServerSpec,
        UserSupSpec,
        RoomSupSpec,
        ConnectionSupSpec
    ],
    
    io:format("[SUPERVISOR] Supervision tree initialized~n"),
    io:format("[SUPERVISOR] Strategy: one_for_one, Intensity: 10, Period: 60s~n"),
    io:format("[SUPERVERVISOR] Children: config, server, user_sup, room_sup, connection_sup~n"),
    
    {ok, {Strategy, Children}}.

