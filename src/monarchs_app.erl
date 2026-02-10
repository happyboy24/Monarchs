-module(monarchs_app).
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% Application start
start(_Type, _Args) ->
    %% Load configuration first
    ok = monarchs_config:start_link(),
    
    io:format("~n========================================~n", []),
    io:format("   MONARCHS CHAT SERVER v2.0.0~n", []),
    io:format("   Production-Ready Edition~n", []),
    io:format("========================================~n", []),
    
    %% Get configuration values
    Environment = monarchs_config:get(environment, development),
    BackendPort = monarchs_config:get(backend_port, 5678),
    BcryptCost = monarchs_config:get(bcrypt_cost, 12),
    TokenExpiry = monarchs_config:get(token_expiry, 3600),
    LogLevel = monarchs_config:get(log_level, info),
    
    io:format("[APP] Environment: ~p~n", [Environment]),
    io:format("[APP] BCrypt cost: ~p~n", [BcryptCost]),
    io:format("[APP] Token expiry: ~p seconds~n", [TokenExpiry]),
    io:format("[APP] Log level: ~p~n", [LogLevel]),
    
    %% Configure logger
    configure_logger(LogLevel),
    
    %% Log startup event
    log_audit(register, #{event => application_start, environment => Environment}),
    
    %% Start the supervision tree
    monarchs_sup:start_link().

stop(_State) ->
    log_audit(terminate, #{event => application_stop}),
    io:format("[APP] Monarchs server shutting down...~n"),
    ok.

%% Configure structured logging
configure_logger(Level) ->
    %% Set Erlang logger level
    case Level of
        debug ->
            ok = logger:set_level(debug);
        info ->
            ok = logger:set_level(info);
        warn ->
            ok = logger:set_level(warning);
        error ->
            ok = logger:set_level(error);
        _ ->
            ok = logger:set_level(info)
    end,
    
    %% Add standard formatter
    ok = logger:add_primary_handler(
        default,
        logger_std_h,
        #{
            level => Level,
            formatter => {monarchs_log_formatter, #{
                time => "H:M:S.Yz",
                level => upper,
                field => message
            }}
        }
    ),
    
    io:format("[APP] Logger configured with level: ~p~n", [Level]).

%% Audit logging helper
log_audit(Event, Data) ->
    case monarchs_config:get(audit_enabled, true) of
        true ->
            LogEntry = #{
                timestamp => erlang:system_time(millisecond),
                event => Event,
                data => Data,
                node => node(),
                application => monarchs
            },
            logger:info("[AUDIT] ~p", [LogEntry]);
        false ->
            ok
    end.

