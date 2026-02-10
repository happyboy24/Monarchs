-module(monarchs_user_sup).
-behaviour(supervisor).

%% API
-export([start_link/0, start_user/1, start_user/2]).

%% Supervisor callbacks
-export([init/1]).

%% Constants
-define(MAX_RESTARTS, 5).
-define(TIME_WINDOW, 60). %% 60 seconds

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Start a user process with just username
start_user(Username) ->
    start_user(Username, undefined).

%% Start a user process with custom settings
start_user(Username, Options) ->
    ChildSpec = #{
        id => Username,
        start => {monarchs_user, start_link, [Username, Options]},
        restart => transient,
        shutdown => 5000,
        type => worker,
        modules => [monarchs_user]
    },
    supervisor:start_child(?MODULE, ChildSpec).

init([]) ->
    io:format("[USER_SUP] User supervisor initialized~n"),
    io:format("[USER_SUP] Strategy: simple_one_for_one, MaxRestarts: ~p, Window: ~ps~n", 
              [?MAX_RESTARTS, ?TIME_WINDOW]),
    
    {ok, {{simple_one_for_one, ?MAX_RESTARTS, ?TIME_WINDOW}, []}}.

