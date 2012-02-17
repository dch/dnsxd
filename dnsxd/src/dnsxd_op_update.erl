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
-module(dnsxd_op_update).
-include("dnsxd_internal.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx, #dns_message{} = Msg) ->
    Msg0 = lower_names(Msg),
    LogProps = build_log(MsgCtx, Msg0),
    case parse_request(Msg0) of
	{ok, {Zone, Lease, PreReq, Changes}} ->
	    Ds = dnsxd:datastore(),
	    case Ds:dnsxd_dns_update(MsgCtx, Zone, Lease, PreReq, Changes) of
		{ok, Lease0} ->
		    ReplyProps = [{rc, ?DNS_RCODE_NOERROR}],
		    LogProps0 = ReplyProps ++ LogProps,
		    case is_integer(Lease) andalso is_integer(Lease0) of
			true ->
			    UL = #dns_opt_ul{lease = Lease0},
			    dnsxd:log(MsgCtx, [{lease, Lease0}|LogProps0]),
			    dnsxd_op_ctx:reply(MsgCtx, Msg, [UL|ReplyProps]);
			false ->
			    dnsxd:log(MsgCtx, LogProps0),
			    dnsxd_op_ctx:reply(MsgCtx, Msg, ReplyProps)
		    end;
		{error, RC} when is_integer(RC) ->
		    ReplyProps = [{rc, RC}],
		    LogProps0 = ReplyProps ++ LogProps,
		    case is_integer(Lease) of
			true ->
			    dnsxd:log(MsgCtx, [{lease, Lease}|LogProps0]),
			    UL = #dns_opt_ul{lease = Lease},
			    dnsxd_op_ctx:reply(MsgCtx, Msg, [UL|ReplyProps]);
			false ->
			    dnsxd:log(MsgCtx, LogProps0),
			    dnsxd_op_ctx:reply(MsgCtx, Msg, ReplyProps)
		    end;
		{error, timeout} ->
		    ?DNSXD_ERR("Update request for ~s timed out", [Zone])
	    end
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

lower_names(#dns_message{questions = [#dns_query{name = QName} = Q],
			 answers = An,
			 authority = Au} = Msg) ->
    Msg#dns_message{questions = [Q#dns_query{name = dns:dname_to_lower(QName)}],
		    answers = lower_names(An),
		    authority = lower_names(Au)};
lower_names(RRs) when is_list(RRs) ->
    [ RR#dns_rr{name = dns:dname_to_lower(Name)}
      || #dns_rr{name = Name} = RR <- RRs ].

build_log(MsgCtx, #dns_message{questions = [#dns_query{name = ZoneName}]}) ->
    build_log(MsgCtx, [{op, ?DNS_OPCODE_UPDATE}, {zone, ZoneName}]);
build_log(MsgCtx, Props) ->
    case dnsxd_op_ctx:tsig(MsgCtx) of
	#dnsxd_tsig_ctx{keyname = KeyName} -> [{keyname, KeyName}|Props];
	_ -> Props
    end.

parse_request(#dns_message{questions = [#dns_query{name = ZoneName}]} = Msg) ->
    Lease = get_lease(Msg),
    case parse_prereq(ZoneName, Msg) of
	{ok, PreReq} ->
	    case parse_changes(ZoneName, Msg) of
		{ok, Changes} -> {ok, {ZoneName, Lease, PreReq, Changes}};
		{error, _RC} = Error -> Error
	    end;
	{error, _RC} = Error -> Error
    end.

get_lease(#dns_message{additional = [#dns_optrr{data = Data}|_]}) ->
    case lists:keyfind(dns_opt_ul, 1, Data) of
	#dns_opt_ul{lease = Lease} when Lease > 0 -> Lease;
	_ -> undefined
    end;
get_lease(#dns_message{}) -> undefined.

parse_prereq(ZoneName, #dns_message{answers = PreReqs}) ->
    case prescan(ZoneName, PreReqs) of
	ok -> parse_prereq(PreReqs, []);
	{error, _RC} = Error -> Error
    end;
parse_prereq([RR|RRs], PreReqs) ->
    case rr_to_prereq(RR) of
	{error, _RC} = Error -> Error;
	PreReq -> parse_prereq(RRs, [PreReq|PreReqs])
    end;
parse_prereq([], PreReqs) -> {ok, lists:reverse(PreReqs)}.

rr_to_prereq(#dns_rr{name = Name,
		     class = ?DNS_CLASS_NONE,
		     type = ?DNS_TYPE_ANY,
		     data = <<>>}) ->
    {not_exist, Name};
rr_to_prereq(#dns_rr{name = Name,
		     class = ?DNS_CLASS_NONE,
		     type = Type,
		     data = <<>>}) ->
    {not_exist, {Name, Type}};
rr_to_prereq(#dns_rr{name = Name,
		     class = ?DNS_CLASS_ANY,
		     type = ?DNS_CLASS_ANY,
		     data = <<>>}) ->
    {exist, Name};
rr_to_prereq(#dns_rr{name = Name,
		     class = ?DNS_CLASS_ANY,
		     type = Type,
		     data = <<>>}) ->
    {exist, {Name, Type}};
rr_to_prereq(#dns_rr{name = Name,
		     class = ?DNS_CLASS_IN,
		     type = Type,
		     data = Data}) ->
    {exist, {Name, Type, Data}};
rr_to_prereq(#dns_rr{}) -> {error, ?DNS_RCODE_FORMERR}.

parse_changes(ZoneName, #dns_message{authority = Changes}) ->
    case prescan(ZoneName, Changes) of
	ok -> parse_changes(Changes, []);
	{error, _RC} = Error -> Error
    end;
parse_changes([RR|RRs], Changes) ->
    case rr_to_change(RR) of
	{error, _RC} = Error -> Error;
	Change -> parse_changes(RRs, [Change|Changes])
    end;
parse_changes([], Changes) -> {ok, lists:reverse(Changes)}.

rr_to_change(#dns_rr{name = Name,
		     class = ?DNS_CLASS_IN,
		     type = Type,
		     ttl = TTL,
		     data = Data}) ->
    {add, {Name, Type, TTL, Data}};
rr_to_change(#dns_rr{name = Name,
		     class = ?DNS_CLASS_ANY,
		     type = ?DNS_TYPE_ANY,
		     data = <<>>}) ->
    {delete, Name};
rr_to_change(#dns_rr{name = Name,
		     class = ?DNS_CLASS_ANY,
		     type = Type,
		     data = <<>>}) ->
    {delete, {Name, Type}};
rr_to_change(#dns_rr{name = Name,
		     class = ?DNS_CLASS_NONE,
		     type = Type,
		     data = Data}) ->
    {delete, {Name, Type, Data}};
rr_to_change(_RR) -> {error, ?DNS_RCODE_FORMERR}.

prescan(_ZoneName, []) -> ok;
prescan(_ZoneName, [#dns_rr{type = Type}|_])
  when Type =:= ?DNS_TYPE_AXFR orelse
       Type =:= ?DNS_TYPE_MAILA orelse
       Type =:= ?DNS_TYPE_MAILB -> {error, ?DNS_RCODE_FORMERR};
prescan(_ZoneName, [#dns_rr{class = Class, type = ?DNS_TYPE_ANY}|_])
  when Class =:= ?DNS_CLASS_IN orelse Class =:= ?DNS_CLASS_NONE ->
    {error, ?DNS_RCODE_FORMERR};
prescan(_ZoneName, [#dns_rr{class = ?DNS_CLASS_ANY, ttl = TTL, data = Data}|_])
  when TTL =/= 0 orelse Data =/= <<>> -> {error, ?DNS_RCODE_FORMERR};
prescan(_ZoneName, [#dns_rr{class = ?DNS_CLASS_NONE, ttl = TTL}|_])
  when TTL =/= 0 -> {error, ?DNS_RCODE_FORMERR};
prescan(ZoneName, [#dns_rr{name = ZoneName}|RRs]) -> prescan(ZoneName, RRs);
prescan(ZoneName, [#dns_rr{name = Name}|RRs]) ->
    NameSize = byte_size(Name),
    ZoneNameSize = byte_size(ZoneName),
    ChildLabelsSize = NameSize - ZoneNameSize - 1,
    case Name of
	<<_:ChildLabelsSize/binary, $., ZoneName/binary>> ->
	    prescan(ZoneName, RRs);
	_ -> {error, ?DNS_RCODE_NOTZONE}
    end.
