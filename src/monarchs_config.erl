-module(monarchs_config).
-behaviour(gen_server).

%% API
-export([
    start_link/0,
    get/1,
    get/2,
    reload/0,
    get_env/2
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
    config :: map(),
    loaded_at :: integer()
}).

%% Default configuration
-define(DEFAULT_CONFIG, #{
    environment => production,
    
    %% Backend settings
    backend_host => "0.0.0.0",
    backend_port => 5678,
    max_connections => 10000,
    accept_pool_size => 10,
    
    %% Security settings
    bcrypt_cost => 12,
    token_expiry => 3600,
    refresh_token_expiry => 86400,
    max_login_attempts => 5,
    rate_limit_window => 60000,
    ban_duration => 300000,
    
    %% Password requirements
    password_min_length => 8,
    password_max_length => 128,
    password_require_uppercase => true,
    password_require_lowercase => true,
    password_require_numbers => true,
    password_require_special => false,
    
    %% Username requirements
    username_min_length => 3,
    username_max_length => 30,
    username_pattern => "^[a-zA-Z0-9_]+$",
    
    %% Logging
    log_level => info,
    log_format => json,
    audit_enabled => true,
    
    %% Monitoring
    health_enabled => true,
    metrics_enabled => true,
    
    %% Features
    private_messaging => true,
    user_room_creation => true,
    guest_access => false,
    end_to_end_encryption => false
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Get a configuration value
get(Key) ->
    get(Key, undefined).

%% Get a configuration value with default
get(Key, Default) ->
    case gen_server:call(?SERVER, {get, Key}) of
        undefined when Default =/= undefined ->
            Default;
        undefined ->
            {error, {missing_config, Key}};
        Value ->
            Value
    end.

%% Reload configuration from file
reload() ->
    gen_server:call(?SERVER, reload).

%% Get environment variable with default
get_env(EnvVar, Default) ->
    case os:getenv(EnvVar) of
        false -> Default;
        Value -> Value
    end.

%% gen_server callbacks
init([]) ->
    Config = load_config(),
    io:format("[CONFIG] Loading configuration...~n"),
    io:format("[CONFIG] Environment: ~p~n", [maps:get(environment, Config)]),
    io:format("[CONFIG] Backend port: ~p~n", [maps:get(backend_port, Config)]),
    io:format("[CONFIG] Token expiry: ~p seconds~n", [maps:get(token_expiry, Config)]),
    io:format("[CONFIG] BCrypt cost: ~p~n", [maps:get(bcrypt_cost, Config)]),
    {ok, #state{
        config = Config,
        loaded_at = erlang:system_time(second)
    }}.

handle_call({get, Key}, _From, State) ->
    Value = maps:get(Key, State#state.config, undefined),
    {reply, Value, State};

handle_call(reload, _From, State) ->
    NewConfig = load_config(),
    {reply, {ok, reloaded}, State#state{config = NewConfig, loaded_at = erlang:system_time(second)}};

handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal functions
load_config() ->
    Config = load_yaml_config(),
    EnvConfig = load_env_config(),
    merge_config(Config, EnvConfig).

load_yaml_config() ->
    case file:consult("config.yaml") of
        {ok, [YamlConfig]} ->
            YamlConfig;
        {error, enoent} ->
            io:format("[CONFIG] config.yaml not found, using defaults~n"),
            #{};
        {error, Reason} ->
            io:format("[CONFIG] Error loading config.yaml: ~p~n", [Reason]),
            #{}
    end.

load_env_config() ->
    #{
        backend_port => get_env("MONARCHS_PORT", undefined),
        backend_host => get_env("MONARCHS_HOST", undefined),
        token_expiry => get_env("MONARCHS_TOKEN_EXPIRY", undefined),
        bcrypt_cost => get_env("MONARCHS_BCRYPT_COST", undefined),
        log_level => get_env("MONARCHS_LOG_LEVEL", undefined),
        token_secret => get_env("MONARCHS_TOKEN_SECRET", undefined),
        database_url => get_env("MONARCHS_DB_URL", undefined),
        redis_url => get_env("MONARCHS_REDIS_URL", undefined)
    }.

merge_config(Default, Override) ->
    maps:merge(Default, maps:filter(fun(_, V) -> V =/= undefined end, Override)).

