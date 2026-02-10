-module(monarchs_connection_sup).
-behaviour(supervisor).

%% API
-export([start_link/0, start_connection/1]).

%% Supervisor callbacks
-export([init/1]).

%% Constants
-define(MAX_RESTARTS, 100).
-define(TIME_WINDOW, 60). %% 60 seconds

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Start a connection handler process
start_connection(Socket) ->
    start_connection(Socket, #{}).

%% Start a connection handler with options
start_connection(Socket, Options) ->
    ChildSpec = #{
        id => make_ref(),
        start => {monarchs_connection, start_link, [Socket, Options]},
        restart => transient,
        shutdown => 3000,
        type => worker,
        modules => [monarchs_connection]
    },
    supervisor:start_child(?MODULE, ChildSpec).

init([]) ->
    io:format("[CONNECTION_SUP] Connection supervisor initialized~n"),
    io:format("[CONNECTION_SUP] Strategy: simple_one_for_one, MaxRestarts: ~p, Window: ~ps~n",
              [?MAX_RESTARTS, ?TIME_WINDOW]),
    
    {ok, {{simple_one_for_one, ?MAX_RESTARTS, ?TIME_WINDOW}, []}}.

