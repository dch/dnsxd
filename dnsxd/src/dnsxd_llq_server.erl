%% -------------------------------------------------------------------
%%
%% Copyright (c) 2011 Andrew Tunnell-Jones. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(dnsxd_llq_server).
-include("dnsxd_internal.hrl").
-behaviour(gen_server).

%% API
-export([start_link/6, handle_msg/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(DEFAULT_MAX_LEASE_LIFE, 7200).
-define(DEFAULT_MIN_LEASE_LIFE, 1800).
-define(DEFAULT_KEEPALIVE, 29).

-record(state, {id,
		zonename,
		msgctx,
		q,
		do_dnssec,
		active = false,
		answers = [],
		expire,
		expire_ref,
		protocol,
		protocol_pid,
		protocol_ref,
		zone_changed = false,
		pending_events = [],
		event_ref
	       }).
-record(event, {id, changes, send_count, last_sent = dns:unix_time()}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Pid, Id, ZoneName, MsgCtx, Q, DoDNSSEC) ->
    Args = [Pid, Id, ZoneName, MsgCtx, Q, DoDNSSEC],
    gen_server:start_link(?MODULE, Args, []).

handle_msg(Pid, MsgCtx,
	   #dns_message{
		  qc = 1, adc = 1,
		  questions = [#dns_query{}],
		  additional = [#dns_optrr{data = [#dns_opt_llq{} = LLQ]}]
		 } = Msg) ->
    handle_msg(Pid, MsgCtx, Msg, LLQ).

handle_msg(Pid, MsgCtx, #dns_message{} = Msg, #dns_opt_llq{errorcode = Error})
  when Error =/= ?DNS_LLQERRCODE_NOERROR ->
    gen_server:call(Pid, {error, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP, id = 0}) ->
    gen_server:call(Pid, {setup_request, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP}) ->
    gen_server:call(Pid, {setup_response, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = ?DNS_LLQOPCODE_REFRESH, leaselife = 0}) ->
    gen_server:call(Pid, {cancel_lease, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = ?DNS_LLQOPCODE_REFRESH}) ->
    gen_server:call(Pid, {renew_lease, MsgCtx, Msg});
handle_msg(Pid, MsgCtx, #dns_message{} = Msg,
	   #dns_opt_llq{opcode = ?DNS_LLQOPCODE_EVENT}) ->
    gen_server:call(Pid, {event, MsgCtx, Msg}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Pid, Id, ZoneName, MsgCtx, Q, DoDNSSEC]) ->
    {Proto, ProtoPid, ProtoRef} = case dnsxd_op_ctx:protocol(MsgCtx) of
				      udp -> {udp, undefined, undefined};
				      tcp ->
					  {tcp, Pid,
					   erlang:monitor(process, Pid)}
				  end,
    State = set_lease_life(?DEFAULT_MAX_LEASE_LIFE,
			   #state{id = Id,
				  zonename = ZoneName,
				  msgctx = MsgCtx,
				  q = Q,
				  do_dnssec = DoDNSSEC,
				  protocol = Proto,
				  protocol_pid = ProtoPid,
				  protocol_ref = ProtoRef}),
    {ok, State}.

handle_call({error, _MsgCtx, Msg}, _From, #state{} = State) ->
    ?DNSXD_ERR("LLQ client reported error:~nMessage:~n~p~nState:~p~n",
	       [Msg, State]),
    {stop, normal, ok, State};
handle_call({setup_request, MsgCtx, Msg}, _From,
	    #state{active = false, id = Id, do_dnssec = DoDNSSEC} = State) ->
    #dns_opt_llq{leaselife = ReqLeaseLife} = ReqLLQ = extract_llq(Msg),
    State0 = set_lease_life(ReqLeaseLife, State),
    RespLLQ = ReqLLQ#dns_opt_llq{id = Id, leaselife = lease_life(State)},
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, RespLLQ]),
    {reply, ok, State0};
handle_call({setup_response, MsgCtx, Msg}, _From,
	    #state{id = Id, do_dnssec = DoDNSSEC} = State) ->
    ok = stop_event_timer(State),
    #dns_opt_llq{id = Id, leaselife = ReqLeaseLife} = ReqLLQ = extract_llq(Msg),
    State0 = State#state{active = true, answers = [], pending_events = []},
    State1 = set_lease_life(ReqLeaseLife, State0),
    RespLLQ = ReqLLQ#dns_opt_llq{id = Id, leaselife = lease_life(State1)},
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, RespLLQ]),
    State2 = send_changes(State1),
    State3 = set_event_timer(State2),
    {reply, ok, State3};
handle_call({cancel_lease, MsgCtx, Msg}, _From,
	    #state{active = true, id = Id, do_dnssec = DoDNSSEC} = State) ->
    #dns_opt_llq{id = Id, leaselife = 0} = LLQ = extract_llq(Msg),
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, LLQ]),
    {stop, normal, ok, State};
handle_call({renew_lease, MsgCtx, Msg}, _From,
	   #state{active = true, id = Id, do_dnssec = DoDNSSEC} = State) ->
    ok = stop_event_timer(State),
    #dns_opt_llq{id = Id, leaselife = ReqLeaseLife} = ReqLLQ = extract_llq(Msg),
    State0 = set_lease_life(ReqLeaseLife, State),
    RespLLQ = ReqLLQ#dns_opt_llq{leaselife = lease_life(State0)},
    ok = dnsxd_op_ctx:reply(MsgCtx, Msg, [{dnssec, DoDNSSEC}, RespLLQ]),
    State1 = set_event_timer(State0),
    {reply, ok, State1};
handle_call({event, _MsgCtx, #dns_message{id = EventId}}, _From,
	    #state{active = true, zone_changed = ZoneChanged} = State) ->
    ok = stop_event_timer(State),
    State0 = ack_event(EventId, State),
    State1 = case ZoneChanged of
		 false -> State0;
		 true -> send_changes(State0)
	     end,
    State2 = set_event_timer(State1),
    {reply, ok, State2};
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast({zone_changed, ZoneName},
	    #state{zonename = ZoneName, active = true,
		   pending_events = Events} = State) ->
    ok = stop_event_timer(State),
    State0 = case Events =:= [] of
		 true -> send_changes(State);
		 false -> State#state{zone_changed = true}
	     end,
    State1 = set_event_timer(State0),
    {noreply, State1};
handle_cast({zone_changed, ZoneName}, #state{zonename = ZoneName} = State) ->
    {noreply, State};
handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info({'DOWN', Ref, _Type, _Object,_Info},
	    #state{protocol_ref = Ref} = State) ->
    ?DNSXD_INFO("Transport down. Stopping"),
    {stop, normal, State};
handle_info(expire, #state{} = State) ->
    ?DNSXD_INFO("Expired. Stopping"),
    {stop, normal, State};
handle_info(keepalive, #state{pending_events = []} = State) ->
    ok = stop_event_timer(State),
    State0 = send_changes(State),
    State1 = set_event_timer(State0),
    {noreply, State1};
handle_info(keepalive, #state{} = State) ->
    {noreply, State};
handle_info(resend, #state{} = State) ->
    ok = stop_event_timer(State),
    case resend_changes(State) of
	{ok, missing_ack} ->
	    ?DNSXD_INFO("Client not-responding - exiting"),
	    {stop, normal, State};
	{ok, #state{} = State0} -> {noreply, set_event_timer(State0)}
    end;
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

extract_llq(
  #dns_message{additional = [#dns_optrr{data = [#dns_opt_llq{} = LLQ]}]}
 ) -> LLQ.

lease_life(#state{expire = Expire}) ->
    case Expire - dns:unix_time() of
	LeaseLife when LeaseLife < 0 -> 0;
	LeaseLife -> LeaseLife
    end.

set_lease_life(RequestedLeaseLife, #state{expire_ref = Ref} = State) ->
    ok = dnsxd_lib:cancel_timer(Ref),
    ok = flush(expire),
    MaxLeaseLife = max_lease_life(),
    MinLeaseLife = min_lease_life(),
    GrantedLeaseLife = if RequestedLeaseLife > MaxLeaseLife -> MaxLeaseLife;
			  RequestedLeaseLife < MinLeaseLife -> MinLeaseLife;
			  true -> RequestedLeaseLife end,
    Expire = dns:unix_time() + GrantedLeaseLife,
    Ref0 = erlang:send_after(GrantedLeaseLife * 1000, self(), expire),
    State#state{expire = Expire, expire_ref = Ref0}.

resend_changes(#state{pending_events = Events} = State) ->
    Now = dns:unix_time(),
    resend_changes(Now, State#state{pending_events = []}, Events).

resend_changes(_Now, #state{} = State, []) ->
    {ok, State};
resend_changes(Now, #state{pending_events = Checked} = State,
	       [#event{send_count = 3, last_sent = LastSent} = Event
		|Unchecked]) ->
    case (LastSent + 8) =< Now of
	true -> {ok, missing_ack};
	false ->
	    State0 = State#state{pending_events = [Event|Checked]},
	    resend_changes(Now, State0, Unchecked)
    end;
resend_changes(Now, #state{id = LLQId, q = Q, msgctx = MsgCtx,
			   do_dnssec = DoDNSSEC,
			   pending_events = Checked} = State,
	       [#event{id = MsgId, send_count = Count, last_sent = LastSent,
		       changes = Changes}|Unchecked])
  when (LastSent + Count * 2) =< Now ->
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_EVENT,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = LLQId,
		       leaselife = lease_life(State)},
    OptRR = #dns_optrr{dnssec = DoDNSSEC, data = [LLQ]},
    Msg = #dns_message{id = MsgId, qr = true, aa = true,
		       qc = 1, questions = [Q],
		       anc = length(Changes), answers = Changes,
		       adc = 1, additional = [OptRR]},
    ok =  dnsxd_op_ctx:to_wire(MsgCtx, Msg),
    Event = #event{id = MsgId, changes = Changes, send_count = Count + 1,
		   last_sent = Now},
    State0 = State#state{pending_events = [Event|Checked]},
    resend_changes(Now, State0, Unchecked);
resend_changes(Now, #state{pending_events = Checked} = State,
	       [Event|Unchecked]) ->
    State0 = State#state{pending_events = [Event|Checked]},
    resend_changes(Now, State0, Unchecked).

send_changes(#state{id = LLQId, zonename = ZoneName, q = Q, msgctx = MsgCtx,
		    do_dnssec = DoDNSSEC, answers = Ans,
		    pending_events = Events} = State) ->
    {Ans0, Changes} = changes(ZoneName, Q, DoDNSSEC, Ans),
    Events0 = send_changes(Events, MsgCtx, LLQId, Q, DoDNSSEC, Changes,
			   lease_life(State)),
    State#state{answers = Ans0, pending_events = Events0, zone_changed = false}.

send_changes(Events, MsgCtx, LLQId, Q, DoDNSSEC, Changes, LeaseLife) ->
    MsgId = send_changes_mkid(Events),
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_EVENT,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = LLQId,
		       leaselife = LeaseLife},
    MaxSize = case dnsxd_op_ctx:protocol(MsgCtx) of
		  tcp -> 65535;
		  _ -> dnsxd_op_ctx:max_size(MsgCtx)
	      end,
    OptRR = #dns_optrr{udp_payload_size = MaxSize, dnssec = DoDNSSEC,
		       data = [LLQ]},
    Msg = #dns_message{id = MsgId, qr = true, aa = true,
		       questions = [Q],
		       answers = Changes,
		       additional = [OptRR]},
    case dns:encode_message(Msg, [{max_size, MaxSize},{tc_mode, llq_event}]) of
	{false, Bin} when is_binary(Bin) ->
	    dnsxd_op_ctx:send(MsgCtx, Bin),
	    Event = #event{id = MsgId, changes = Changes, send_count = 1},
	    [Event|Events];
	{true, Bin, #dns_message{answers = LeftoverChanges}} ->
	    dnsxd_op_ctx:send(MsgCtx, Bin),
	    Changes0 = Changes -- LeftoverChanges,
	    Event = #event{id = MsgId, changes = Changes0, send_count = 1},
	    Events0 = [Event|Events],
	    send_changes(Events0, MsgCtx, LLQId, Q, DoDNSSEC, LeftoverChanges,
			 LeaseLife)
    end.

send_changes_mkid(Events) ->
    Id = dns:random_id(),
    case lists:keymember(Id, #event.id, Events) of
	true -> send_changes_mkid(Events);
	false -> Id
    end.

set_event_timer(#state{pending_events = Events} = State) ->
    ok = stop_event_timer(State),
    {After, Message} = case Events =:= [] of
			   true -> {keep_alive_period(), keepalive};
			   false -> {next_resend(Events), resend}
		       end,
    Ref0 = erlang:send_after(After, self(), Message),
    State#state{event_ref = Ref0}.

stop_event_timer(#state{event_ref = Ref}) ->
    ok = dnsxd_lib:cancel_timer(Ref),
    ok = flush(resend),
    ok = flush(keepalive).

flush(Term) -> receive Term -> flush(Term) after 0 -> ok end.

next_resend(Events) ->
    Fun = fun(#event{last_sent = LastSent, send_count = Count}, Tmp) ->
		  case LastSent + Count * 2 of
		      Tmp0 when Tmp =:= undefined orelse Tmp0 < Tmp -> Tmp0;
		      _ -> Tmp
		  end
	  end,
    SecondsAway = lists:foldl(Fun, undefined, Events) - dns:unix_time(),
    if SecondsAway < 0 -> 0; true -> SecondsAway * 1000 end.

changes(_ZoneName, #dns_query{name = QName, type = Type}, DNSSEC, LastAns) ->
    Name = dns:dname_to_lower(QName),
    ZoneRef = dnsxd_ds_server:find_zone(Name),
    CurAns = case dnsxd_ds_server:get_set(ZoneRef, Name, Type) of
		 [] -> [];
		 [#rrset{} = Set] -> set_to_ans(QName, Set, DNSSEC)
	     end,
    Added = [ RR#dns_rr{ttl = 1} || RR <- CurAns -- LastAns ],
    Removed =[ RR#dns_rr{ttl = -1} || RR <- LastAns -- CurAns ],
    {CurAns, Added ++ Removed}.

set_to_ans(QName, #rrset{type = Type, data = Datas}, false) ->
    [ #dns_rr{name = QName, type = Type, ttl = undefined, data = Data}
      || Data <- Datas ];
set_to_ans(QName, #rrset{sig = Sigs} = Set, true) ->
    RR = set_to_ans(QName, Set, false),
    lists:foldr(fun(Sig, Acc) ->
			[#dns_rr{name = QName, type = ?DNS_TYPE_RRSIG,
				 ttl = undefined, data = Sig}|Acc]
		end, RR, Sigs).

ack_event(EventId, #state{pending_events = Events} = State) ->
    case lists:keytake(EventId, #event.id, Events) of
	{value, _Event, Events0} -> State#state{pending_events = Events0};
	false -> State
    end.

max_lease_life() ->
    proplists:get_value(max_length, llq_opts(), ?DEFAULT_MAX_LEASE_LIFE).

min_lease_life() ->
    proplists:get_value(min_length, llq_opts(), ?DEFAULT_MIN_LEASE_LIFE).

keep_alive_period() ->
    proplists:get_value(udp_keepalive, llq_opts(), ?DEFAULT_KEEPALIVE) * 1000.

llq_opts() ->
    case dnsxd:get_env(llq_opts) of
	{ok, List} when is_list(List) -> List;
	undefined -> {ok, []};
	_ -> throw({bad_config, llq_opts})
    end.
