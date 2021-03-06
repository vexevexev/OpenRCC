%Module
-module(open_rcc_server).

%Behaviour
-behaviour(gen_server).

%Start Function
-export([start_link/1, mochiweb_loop_http/1, mochiweb_loop_https/1]).

%Gen_Server API
-export([
	init/1,
	handle_call/3,
	handle_cast/2,
	handle_info/2,
	terminate/2,
	code_change/3
]).

-record(state, {} ). %Empty for now.

%OpenACD
-include_lib("OpenACD/include/log.hrl").
-include_lib("OpenACD/include/call.hrl").
-include_lib("OpenACD/include/agent.hrl").
-include_lib("OpenACD/include/queue.hrl").
-include_lib("OpenACD/include/web.hrl").

%% HTTP routines and Responses
-define(RESP_AGENT_NOT_LOGGED, {200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Agent is not logged in">>)}).
-define(RESP_SUCCESS, {200, [{"Content-Type", "application/json"}], encode_response(<<"true">>)}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Gen_Server Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link(Port) ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, [Port], []).

init([Port]) ->
	start_mochiweb(Port),
	{ok, #state{}}.

handle_call({Resource, Req}, _From, State) ->
	QueryString = Req:parse_qs(),
	handle_request(Resource, QueryString, Req),
	{reply, ok, State}.

%% We need these to crash the process early if we starts using gen_cast&gen_info
%% somewhere in the code. But we cannot just remove them since the compiler
%% will show warnings abount unimplemented gen_server callbacks
handle_cast(undefined, State) ->
	{noreply, State}.
handle_info(undefined, State) ->
	{noreply, State}.

terminate(normal, _State) ->
	mochiweb_http:stop(),
	ok;
terminate(_Reason, _State) ->
	ok.

code_change(_, _, State) ->
	{ok, State}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Mochi-Web Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_mochiweb(Port) ->
	%% We need to do start_link there to link Mochiweb process into Supervision tree
	%% This process will die if Mochiweb process dies. 
	%% Thus Supervisor has an opportunity to restar boths.
	try
		case application:get_env(open_rcc, use_https) of
			{ok, true} ->
				{ok, Password} = application:get_env(open_rcc, orcc_password),
				{ok, SslCertfile} = application:get_env(open_rcc, cert_file),
				{ok, SslKeyfile} = application:get_env(open_rcc, key_file),
				
				security_manager:start_link(Password),
				mochiweb_http:start([
									{port, Port}, 
									{ssl, true},
										  {ssl_opts, [
												{certfile, SslCertfile},
												{keyfile, SslKeyfile}
											   ]},
									{loop, {?MODULE, mochiweb_loop_https}}]);
			_Else ->
				mochiweb_http:start([{port, Port}, {loop, {?MODULE, mochiweb_loop_http}}])
		end
	catch
		W:Y ->
			Trace = erlang:get_stacktrace(),
			?ERROR("Error starting OpenRCC!!! Here are the details:~n
					{~p, ~p}~n
					Stack Trace:~n
					~p", 
					[W, Y, Trace])
	end.

mochiweb_loop_http(Req) ->
	Path = Req:get(path),
	Resource = case string:str(Path, "?") of
						0 -> Path;
						N -> string:substr(Path, 1, length(Path) - (N + 1))
			   end,
	try 
		  QueryString = mochiweb_util:parse_qs(Req:recv_body()),
		  ?INFO("Received Parsed Request:~n{~p, ~p}", [Resource, QueryString]),
		handle_request(Resource, QueryString, Req)
	catch
		%% There is always a posibility that agent or call process will die just before we call it
		%% Also REST call could have invalid PID and we cannot check it for sure since there is no
		%% clear way how to check PIDs on remote node
		exit:{noproc, _Rest} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Invalid PID, Agent process has died, or Invalid parameters.">>)})
	end.

mochiweb_loop_https(Req) ->
	 
	Path = Req:get(path),
	Resource = case string:str(Path, "?") of
				   0 -> Path;
				   N -> string:substr(Path, 1, length(Path) - (N + 1))
			   end,
	try 
		QueryString = mochiweb_util:parse_qs(Req:recv_body()),
		  
		?INFO("Received Parsed Request:~n{~p, ~p}", [Resource, QueryString]),
		  
		case gen_server:call(security_manager, {check_credentials, list_to_integer(proplists:get_value("seconds", QueryString, "1")), 
																				   list_to_integer(proplists:get_value("microsecs", QueryString, "1")),
																				   proplists:get_value("orcc_password", QueryString, undefined)}) of
			allow -> 
				handle_request(Resource, QueryString, Req);
			deny ->
				?WARNING("INTRUSION_ATTEMPT: Mochiweb request was: ~n~p", [Req]),
				Req:respond({200, [{"Content-Type", "application/json"}], 
							encode_response(<<"false">>, <<"Invalid credentials. This incident has been logged and reported.">>)})
		end
	catch
		%% There is always a posibility that agent or call process will die just before we call it
		%% Also REST call could have invalid PID and we cannot check it for sure since there is no
		%% clear way how to check PIDs on remote node
		exit:{noproc, _Rest} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Invalid PID or Agent process has died.">>)});
		W:Y ->
			%% catch-all for all other unexpected exceptions
			Trace = erlang:get_stacktrace(),
			?ERROR("Error in OpenRCC (it is possible this error was gnerated by an intrusion attempt): {~p, ~p}~nStack Trace:~n~p", [W, Y, Trace]),

			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Unknown error.">>)})
	end.
	
%%--------------------------------------------------------------------
%% @doc
%% For testing purposes. Returns the list of previous_times that have been
%% successfuly authentecated over the past security_manager:?WINDOW/2 seconds
%%	HTTP request - <server:port>/get_previous_times
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/get_previous_times", _QueryString, Req) ->
	 IntegerList = gen_server:call(security_manager, get_previous_times),
	 TimesString = string:join([ erlang:integer_to_list(X) || X <- IntegerList ], ", "),
	Req:respond({200, [{"Content-Type", "application/json"}], mochijson2:encode([{success, <<"true">>}, {times, list_to_binary(TimesString)}])});

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% REST API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%--------------------------------------------------------------------
%% @doc
%% Login an agent in OpenACD. The agent will be unavaible state.
%%	 HTTP request - <server:port>/login?agent=<agent name>&password=<password>&domain=<SIP domain>
%%		 <agent name> - is an agent name.
%%		 <password> - is password in plain text (Unsecured).
%%		 <SIP domain> - SIP domain name
%%	 The method can return:
%%		 200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/login", QueryString, Req) ->
	Username = proplists:get_value("agent", QueryString, ""),
	Password = proplists:get_value("password", QueryString, ""),
	Domain = proplists:get_value("domain", QueryString, "config.acd.dcf.patlive.local"),
	
	Endpointdata = [ Username, "@", Domain | [] ],
	Endpointtype = pstn,
	
	%% Testing parameter
	%% Endpointdata = Username,
	%% Endpointtype = sip_registration,

	Persistance = transient,
	Bandedness = outband,
	
	case agent_manager:query_agent(Username) of 
		false ->
			AuthResult = agent_auth:auth(Username, Password),
			Respond = handle_login(AuthResult, Username, Password, 
								   {Endpointtype, Endpointdata, Persistance}, Bandedness),
			Req:respond(Respond);
		{true, _PID} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Agent already logged in.">>)})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Logout an agent from OpenACD.
%%	HTTP request - <server:port>/logout?agent=<agent name>
%%				 - <server:port>/logout?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/logout", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Respond = ?RESP_AGENT_NOT_LOGGED;
		Pid ->
			agent:stop(Pid),
			Respond = ?RESP_SUCCESS
	end,
	Req:respond(Respond);

%%--------------------------------------------------------------------
%% @doc
%% Adds a skill for a given agent.
%%	HTTP request - <server:port>/add_skill?agent=<agent name>&skill=<new skill>
%%				 - <server:port>/add_skill?agent_pid=<agent pid>&skill=<new skill>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%			<new skill> - the new skill to be added for the given agent.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/add_skill", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			case proplists:get_value("skill", QueryString, "") of
				"" -> 
					Req:respond({200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Please specify a valid skill.">>)});
				Skill ->
					try 
						SkillAtom = erlang:list_to_atom(Skill),
						agent:add_skills(Pid, [SkillAtom]),
						Req:respond(?RESP_SUCCESS)
					catch
						W:Y ->
							Respond = {200, [{"Content-Type", "application/json"}], 
											  encode_response(<<"false">>, 
															  erlang:list_to_binary("Unknown error: " ++ 
															  io_lib:format("~p", [W]) ++ 
															  ":" ++ 
															  io_lib:format("~p", [Y])))},
							Req:respond(Respond)
					end	 
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Removes a skill for a given agent.
%%	HTTP request - <server:port>/remove_skill?username=<agent name>&skill=<skill>
%%				 - <server:port>/remove_skill?agent_pid=<agent pid>&skill=<skill>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%			<new skill> - the skill to be removed from the given agent.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/remove_skill", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			case proplists:get_value("skill", QueryString, "") of
				"" -> 
					Req:respond({200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Please specify a valid skill.">>)});
				Skill ->
					try 
						SkillAtom = erlang:list_to_atom(Skill),
						agent:remove_skills(Pid, [SkillAtom]),
						Req:respond(?RESP_SUCCESS)
					catch
						W:Y ->
							Respond = {200, 
									  [{"Content-Type", "application/json"}], 
									  encode_response(<<"false">>, 
													  erlang:list_to_binary("Unknown error: " ++ 
													  io_lib:format("~p", [W]) ++ 
													  ":" ++ 
													  io_lib:format("~p", [Y])))},
							Req:respond(Respond)
					end	 
			end
	end;
%%--------------------------------------------------------------------
%% @doc
%% Make an agent avaiable for calls.
%%	HTTP request - <server:port>/set_avail?agent=<agent name>
%%				   <server:port>/set_avail?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/set_avail", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			agent:set_state(Pid, idle),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% End current call on agent and put the agent into wrapup state
%%	HTTP request:
%%			 <server:port>/hangup?agent=<agent name>
%%			 <server:port>/hangup?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/hangup", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			%% agent:set_state will not work due to a guard in agent.erl
			#agent{connection=CPid} = agent:dump_state(Pid),
			agent_connection:set_state(CPid, wrapup),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Make an agent avaiable for calls after callwork.
%%	HTTP request: 
%%			 <server:port>/hangup?agent=<agent name>
%%			 <server:port>/hangup?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/end_wrapup", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			%% agent:set_state will not work due to a guard in agent.erl
			#agent{connection=CPid} = agent:dump_state(Pid),
			agent_connection:set_state(CPid, idle),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Returns PID of Agent
%%	HTTP request: 
%%			 <server:port>/get_pid?agent=<agent name>
%%		<agent name> - is an agent name.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/get_pid", QueryString, Req) ->
	AgentName = proplists:get_value("agent", QueryString, ""),
	case agent_manager:query_agent(AgentName) of
		false ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		{true, Pid} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"true">>, [{pid, to_binary(Pid)}])})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Request information about agent's state
%%	HTTP request: 
%%			 <server:port>/get_call_state?agent=<agent name>
%%			 <server:port>/get_call_state?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------	
handle_request("/get_call_state", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{state=State} = agent:dump_state(Pid),
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"true">>, [{call_state, to_binary(State)}])})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Make an agent unavaiable for calls.
%%	HTTP request:
%%			 <server:port>/set_released?agent=<agent name>
%%			 <server:port>/set_released?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/set_released", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			Reason = get_released_reason(QueryString),
			agent:set_state(Pid, released, Reason),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Returns Agent's release state.
%%	HTTP request:
%%			 <server:port>/get_release_state?agent=<agent name>
%%			 <server:port>/get_release_state?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%%				 and Released state
%% @end
%%--------------------------------------------------------------------
handle_request("/get_release_state", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			AgentState = agent:dump_state(Pid),
			case AgentState#agent.statedata of 
				{Id, Label, Bias} ->
					JSON = encode_response(<<"true">>, 
										   [
											{<<"id">>, to_binary(Id)},
											{<<"label">>, to_binary(Label)},
											{<<"bias">>, to_binary(Bias)}
											]);
				Others ->
					JSON = encode_response(<<"true">>, 
										   [{release_data, to_binary(io_lib:format("~w", [Others]))}])
			end,
			Req:respond({200, [{"Content-Type", "application/json"}], JSON})										
	end;

%%--------------------------------------------------------------------
%% @doc
%% Returns Agent's release state.
%%	HTTP request:
%%			 <server:port>/get_release_opts
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%%				 and Released state
%% @end
%%--------------------------------------------------------------------
handle_request("/get_release_opts", _QueryString, Req) ->
	JSON = encode_response(<<"true">>, [ {release_opts, 
										  lists:map( fun relase_opt_record_to_proplist/1, agent_auth:get_releases())}
									   ]),
	 Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Executes silent monitoring of Agent's call. 
%%	 HTTP request: 
%%			  <server:port>/spy?spy=<spy name>&target=<target name>
%%			  <server:port>/spy?spy_pid=<spy pid>&target_pid=<target pid>
%%		  <spy name> is Spy agent name
%%		  <spy pid> is Spy agent pid
%%		  <target name> is Target agent name
%%		  <target pid> is Target agent pid
%%	 The method can return: 
%%		  200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/spy", QueryString, Req) ->
	SpyPid = get_pid(QueryString, "spy_pid", "spy"),
	TargetPid = get_pid(QueryString, "target_pid", "target"),
	case {SpyPid, TargetPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Spy and target agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Spy agent is not logged in">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Target agent is not logged in">>);
		_Else ->
			#agent{statedata = Callrec} = agent:dump_state(TargetPid),
			%% TODO - The operation could fail because a call is dropped just before.
			%% What we need to do there?
			gen_media:spy(Callrec#call.source, SpyPid, agent:dump_state(SpyPid)),
			JSON = encode_response(<<"true">>)
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Executes silent monitoring and whisper to Agent.
%%	 HTTP request: 
%%			  <server:port>/coach?coach=<spy name>&target=<target name>
%%			  <server:port>/couch?couch_pid=<spy pid>&target_pid=<target pid>
%%		  <spy name> is Spy agent name
%%		  <spy pid> is Spy agent pid
%%		  <target name> is Target agent name
%%		  <target pid> is Target agent pid
%%	 The method can return: 
%%		  200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/coach", QueryString, Req) ->
	CoachPid = get_pid(QueryString, "coach_pid", "coach"),
	TargetPid = get_pid(QueryString, "target_pid", "target"),
	case {CoachPid, TargetPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach and target agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Spy agent is not logged in.">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach agent is not logged in.">>);
		_Else ->
			#agent{statedata = Callrec} = agent:dump_state(TargetPid),
			CoachRec = agent:dump_state(CoachPid),

			%% Executes freeswitch_media:spy_single_step in separated process 
			%% since spy_single_step will be blocked until Coach agent picks up a spy call.
			spawn(fun() ->
						  freeswitch_media:spy_single_step(Callrec#call.source, CoachRec, agent)
				  end),
			JSON = encode_response(<<"true">>)
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});


%%--------------------------------------------------------------------
%% @doc
%% Allows a supervisor to join an agent's call.
%%	 HTTP request: 
%%			  <server:port>/join?coach=<spy name>&target=<target name>
%%			  <server:port>/join?couch_pid=<spy pid>&target_pid=<target pid>
%%		  <spy name> is Spy agent name
%%		  <spy pid> is Spy agent pid
%%		  <target name> is Target agent name
%%		  <target pid> is Target agent pid
%%	 The method can return: 
%%		  200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/join", QueryString, Req) ->
	CoachPid = get_pid(QueryString, "coach_pid", "coach"),
	TargetPid = get_pid(QueryString, "target_pid", "target"),
	case {CoachPid, TargetPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach and target agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Spy agent is not logged in.">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach agent is not logged in.">>);
		_Else ->
			#agent{statedata = Callrec} = agent:dump_state(TargetPid),
			CoachRec = agent:dump_state(CoachPid),

			%% Executes freeswitch_media:spy_single_step in separated process 
			%% since spy_single_step will be blocked until Coach agent picks up a spy call.
			spawn(fun() ->
						  freeswitch_media:spy_single_step(Callrec#call.source, CoachRec, both)
				  end),
			JSON = encode_response(<<"true">>)
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from an agent to a queue. The agent will be put in wrapup state
%%	HTTP request: 
%%			 <server:port>/queue_transfer?agent=<agent name>&queue=<queue name>
%%			 <server:port>/queue_transfer?agent_pid=<agent pid>&queue=<queue name>
%%		<agent name> - is an agent name who owns the call
%%		<agent pid> - is an agent pid.
%%		<queue name> - is a queue name where the call will be transfered.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/queue_transfer", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			QueueName = proplists:get_value("queue", QueryString),
			Result = agent:queue_transfer(Pid, QueueName),
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"true">>, [
													  { return, to_binary(Result) }
													  ])})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from one agent to another one.
%%	HTTP request:
%%			 <server:port>/agent_transfer?from=<agent name>&to=<target agent>
%%			 <server:port>/agent_transfer?from_pid=<agent pid>&to_pid=<target pid>
%%		<agent name> - is an agent name whom
%%		<agent pid> - is an agent pid
%%		<target agent> - is target agent name
%%		<target pid> - is target agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/agent_transfer", QueryString, Req) ->
	FromPid = get_pid(QueryString, "from_pid", "from"),
	ToPid = get_pid(QueryString, "to_pid", "to"),
	case {FromPid, ToPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Transferer and Transferee agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Transferer agent is not logged in.">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Transferee agent is not logged in.">>);
		{FromPid, FromPid} ->
			JSON = encode_response(<<"false">>, <<"Transferer and Transferee agents are equal">>);
		_Else ->
			Result = agent:agent_transfer(FromPid, ToPid),
			JSON = encode_response(<<"true">>, [
												{ return, to_binary(Result) }
											   ])
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from an agent to sip endpoint.
%%	HTTP request:
%%			 <server:port>/blind_transfer?agent=<agent name>&dest=<sip endpoint>
%%			 <server:port>/blind_transfer?agent_pid=<agent pid>&dest=<sip endpoint>
%%		<agent name> - is an agent name whom
%%		<agent pid> - is an agent pid
%%		<sip endpoint> - is the target sip endpoint
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/blind_transfer", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata = Callrec} = agent:dump_state(Pid),
			Dest = proplists:get_value("dest", QueryString, unspecified_destination),
			gen_media:cast(Callrec#call.source, {blind_transfer, Dest}),
			Req:respond(?RESP_SUCCESS)
	end;
%%--------------------------------------------------------------------
%% @doc
%% Put agent's call to hold/unhold state
%%	HTTP request: 
%%			 <server:port>/toggle_hold?agent=<agent name>
%%			 <server:port>/toggle_hold?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/toggle_hold", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:toggle_hold(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Dial 3rd party number
%%	HTTP request: 
%%			 <server:port>/contact_3rd_party?agent=<agent name>&dest=<3rd party number>
%%			 <server:port>/contact_3rd_party?agent_pid=<agent pid>&dest=<3rd party number>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%		<3rd party number> - a number to call
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/contact_3rd_party", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			Dest = proplists:get_value("dest", QueryString, unspecified_destination),
			Profile = proplists:get_value("profile", QueryString, "default"),
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:contact_3rd_party(MPid, Dest, '3rd_party', Profile),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Merge Agent, Initial and 3rd party calls into conference
%%	HTTP request: 
%%			 <server:port>/merge_all?agent=<agent name>
%%			 <server:port>/merge_all?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/merge_all", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
		#agent{statedata=Call} = agent:dump_state(Pid),
		#call{source=MPid} = Call,
			freeswitch_media:merge_all(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Merge Only 3rd Party, Place only 3rd party in conference
%%	HTTP request: 
%%			 <server:port>/merge_only_3rd_party?agent=<agent name>
%%			 <server:port>/merge_only_3rd_party?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/merge_only_3rd_party", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:merge_only_3rd_party(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Ends a conference assotiated with the agent and drops all active calls 
%% within the conference
%%	HTTP request: 
%%			 <server:port>/end_conference?agent=<agent name>
%%			 <server:port>/end_conference?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/end_conference", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:end_conference(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Gets the status of the conference of a given agent.
%%	HTTP request: 
%%			 <server:port>/conference_status?agent=<agent name>
%%			 <server:port>/conference_status?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%%				 and the status of the conference.
%% @end
%%--------------------------------------------------------------------  
handle_request("/conference_status", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			{ok, {_ConferenceID, ConferenceData}} = freeswitch_media:conference_status(MPid),
			NewConferenceData = [encode_status(X) || X <- ConferenceData],
			JSON = encode_response(<<"true">>, [ { return, NewConferenceData } ]),
			Req:respond({200, [{"Content-Type", "application/json"}], JSON})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Kicks the given ID out of the given agent's conference.
%%	HTTP request: 
%%			 <server:port>/conference_kick?agent=<agent name>&id=<id>
%%			 <server:port>/conference_kick?agent_pid=<agent pid>&id=<id>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%		<id> - is the ID of the conference member to kick.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field and
%%					  a message describing the failure if there is one.
%% @end
%%--------------------------------------------------------------------  
handle_request("/conference_kick", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			ID = proplists:get_value("id", QueryString),
			case ID of
				undefined ->
					JSON = encode_response(<<"false">>, <<"Undefined client ID number.">>),
					Req:respond({200, [{"Content-Type", "application/json"}], JSON});
				ValidID ->
					#agent{statedata=Call} = agent:dump_state(Pid),
					#call{source=MPid} = Call,
					freeswitch_media:conference_kick(MPid, ValidID),
					Req:respond(?RESP_SUCCESS)
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Hangs up on the third party of a conference.
%%	HTTP request: 
%%			 <server:port>/hangup_3rd_party?agent=<agent name>
%%			 <server:port>/hangup_3rd_party?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/hangup_3rd_party", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:hangup_3rd_party(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Retrieves a conference for a given agent:
%%	HTTP request: 
%%			 <server:port>/retrieve_conference?agent=<agent name>
%%			 <server:port>/retrieve_conference?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/retrieve_conference", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
	   		#call{source=MPid} = Call,
			freeswitch_media:retrieve_conference(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Starts a warm transfer for an agent.
%%	HTTP request: 
%%			 <server:port>/start_warm_transfer?agent=<agent name>&number=<number>
%%			 <server:port>/start_warm_transfer?agent_pid=<agent pid>&number=<number
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%		  <number> - is the number to be transfered to
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/start_warm_transfer", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			Number = proplists:get_value("dest", QueryString, unspecified_number),
			#agent{statedata=Call} = agent:dump_state(Pid),
	   		#call{source=MPid} = Call,
			gen_media:warm_transfer_begin(MPid, Number),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Cancels a warm transfer.
%%	HTTP request: 
%%			 <server:port>/cancel_warm_transfer?agent=<agent name>
%%			 <server:port>/cancel_warm_transfer?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/cancel_warm_transfer", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			#agent{statedata=StateData} = agent:dump_state(Pid),
	   		{onhold, #call{source=MPid}, _, _} = StateData,
			gen_media:warm_transfer_cancel(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Completes a warm transfer.
%%	HTTP request: 
%%			 <server:port>/complete_warm_transfer?agent=<agent name>
%%			 <server:port>/complete_warm_transfer?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/complete_warm_transfer", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			#agent{statedata=StateData} = agent:dump_state(Pid),
	   		{onhold, #call{source=MPid}, _, _} = StateData,
			gen_media:warm_transfer_complete(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

handle_request(_Path, _QueryString, Req) ->
	Req:respond({404, [{"Content-Type", "text/html"}], <<"Not Found">>}).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Checks a authorization result and tries to login an agent into OpenACD
%% @end
%%--------------------------------------------------------------------
handle_login({allow, Id, Skills, Security, Profile}=_AuthResult, 
			 Username, Password, {Endpointtype, Endpointdata, Persistance}=Endpoint, 
			 Bandedness) ->
	Agent = #agent{
	  id = Id, 
	  defaultringpath = Bandedness, 
	  login = Username, 
	  skills = Skills, 
	  profile=Profile, 
	  password=Password,
	  endpointtype = Endpointtype,
	  endpointdata = Endpointdata,
	  security_level = Security
	 },
	{ok, Pid} = agent_connection:start(Agent),
	Node = erlang:node(Pid),
	?INFO("~s logged in with endpoint ~p", [Username, Endpoint]),
	agent_connection:set_endpoint(Pid, {Endpointtype, Endpointdata}, Persistance),
	AgentPid = agent_connection:get_agentpid(Pid),
	{200, [{"Content-Type", "application/json"}], encode_response(<<"true">>, 
										[
										 {node, to_binary(Node)}, 
										 {pid, to_binary(AgentPid)}
									   ])};															 
handle_login(_AuthResult, _Username, _Password, _Endpoint, _Bandedness) ->
	{200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Invalid username and/or password.">>)}.

%%--------------------------------------------------------------------
%% @doc
%% Extracts AgentPID from HTTP Query string.
%% @end
%%--------------------------------------------------------------------
get_agentpid(QueryString) ->
	get_pid(QueryString, "agent_pid", "agent").


%%--------------------------------------------------------------------
%% @doc
%% Extracts PID from Query string. If 'pid' parameter is not defined 
%% when 'agent' will be used to get Agent PID registered in agent_manager
%% @end
%%--------------------------------------------------------------------
get_pid(QueryString, Pid, Name) ->
	case proplists:get_value(Pid, QueryString) of 
		undefined ->
			get_pid(Name, QueryString);
		Value ->
			%% erlang:is_process_alive will not work with remote nodes
			%% So we need another way to check Pid validity
			to_pid(Value)
	end.
get_pid(Name, QueryString) ->
	Value = proplists:get_value(Name, QueryString, ""),
	case agent_manager:query_agent(Value) of
		false ->
			undefined;
		{true, Pid} ->
			Pid
	end.

%%--------------------------------------------------------------------
%% @doc
%% Extract and format Release reason
%% @end
%%--------------------------------------------------------------------
get_released_reason(QueryString) ->
	Id = proplists:get_value("id", QueryString),
	Label = proplists:get_value("label", QueryString),
	Bias = proplists:get_value("bias", QueryString),
	get_released_reason(Id, Label, Bias).

get_released_reason(undefined, _, _) ->
	default;
get_released_reason(_, undefined, _) ->
	default;
get_released_reason(_, _, undefined) ->
	default;
get_released_reason(Id, Label, Bias) ->
	{Id, Label, list_to_integer(Bias)}.

%%--------------------------------------------------------------------
%% @doc
%% Encode responce in JSON format
%% @end
%%--------------------------------------------------------------------
encode_response(Result) ->
	mochijson2:encode([{success, Result}]).

encode_response(Result, Message) when is_binary(Message) ->
	mochijson2:encode([{success, Result}, {message, Message}]);
encode_response(Result, Rest) when is_list(Rest) ->
	mochijson2:encode([{success, Result} | Rest]).

% Utility functions for converting a #release_opt record (located in agent.hrl) into a property list. 
% These functions are used to convert a list of #release_opt's into a JSON string.
relase_opt_record_to_proplist(#release_opt{} = Rec) ->
  lists:zip(record_info(fields, release_opt), lists:map(fun to_binary/1, tl(tuple_to_list(Rec)))).

%%--------------------------------------------------------------------
%% @doc
%% Convert terms into binary format. 
%% List, Atom, Pid, Integer and Binary are supported for now
%% @end
%%--------------------------------------------------------------------
to_binary(Var) when is_list(Var) ->
	list_to_binary(Var);
to_binary(Var) when is_atom(Var) ->
	atom_to_binary(Var, latin1);
to_binary(Var) when is_pid(Var) ->
	list_to_binary(pid_to_list(Var));
to_binary(Var) when is_binary(Var) ->
	Var;
to_binary(Var) when is_integer(Var) ->
	list_to_binary(integer_to_list(Var)).
%%--------------------------------------------------------------------
%% @doc
%% Convert List or Binary to Pid
%% @end
%%--------------------------------------------------------------------
to_pid(Var) when is_binary(Var) ->
	list_to_pid(binary_to_list(Var));
to_pid(Var) when is_list(Var) ->
	list_to_pid(Var);
to_pid(Var) when is_pid(Var) ->
	Var.

%%--------------------------------------------------------------------
%% @doc
%% Encode conference status. Used by handle_request/3
%% @end
%%--------------------------------------------------------------------
encode_status(ConferenceStatus) ->
  [{X,erlang:list_to_binary(Y)} || {X, Y} <- ConferenceStatus].