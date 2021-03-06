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
-module(dnsxd_lib).
-include("dnsxd_internal.hrl").

%% API
-export([ensure_apps_started/1, new_id/0, is_dnssd_rr/2, use_procket/0,
	 procket_open/4, cancel_timer/1, ip_to_txt/1, is_dnssd_change/3]).

%%%===================================================================
%%% API
%%%===================================================================

ensure_apps_started([]) -> ok;
ensure_apps_started([App|Apps]) ->
    case application:start(App) of
	ok -> ensure_apps_started(Apps);
	{error, {already_started, _}} -> ensure_apps_started(Apps);
	{error, _Reason} = Error -> Error
    end.

new_id() ->
    Bin = crypto:sha(term_to_binary({make_ref(), os:timestamp()})),
    new_id(Bin).
new_id(Bin) when is_binary(Bin) ->
    << <<(new_id(I))>> || <<I:5>> <= Bin >>;
new_id(Int)
  when is_integer(Int) andalso Int >= 0 andalso Int =< 9 -> Int + 48;
new_id(Int)
  when is_integer(Int) andalso Int >= 10 andalso Int =< 31 -> Int + 87.

is_dnssd_rr(ZoneName, #dns_rr{name = Name, type = Type}) ->
    is_dnssd_rr(ZoneName, Name, Type);
is_dnssd_rr(ZoneName, #dnsxd_rr{name = Name, type = Type}) ->
    is_dnssd_rr(ZoneName, Name, Type).

is_dnssd_rr(ZoneName, Name, Type) when is_binary(ZoneName) ->
    ZoneNameLabels = dns:dname_to_labels(ZoneName),
    is_dnssd_rr(ZoneNameLabels, Name, Type);
is_dnssd_rr(ZoneNameLabels, Name, ?DNS_TYPE_PTR) ->
    case dns:dname_to_labels(dns:dname_to_lower(Name)) of
	[<<$_, _/binary>>, <<"_sub">>, <<$_, _/binary>>, Proto|ZoneNameLabels]
	  when Proto =:= <<"_tcp">> orelse Proto =:= <<"_udp">> -> true;
	[<<$_, _/binary>>, Proto|ZoneNameLabels]
	  when Proto =:= <<"_tcp">> orelse Proto =:= <<"_udp">> -> true;
	[<<"_services">>, <<"_dns-sd">>, <<"_udp">>|ZoneNameLabels] -> true;
	_ -> false
    end;
is_dnssd_rr(ZoneNameLabels, Name, Type)
  when Type =:= ?DNS_TYPE_SRV orelse Type =:= ?DNS_TYPE_TXT ->
    case dns:dname_to_labels(dns:dname_to_lower(Name)) of
	[_, <<$_, _/binary>>, Proto|ZoneNameLabels] ->
	    Proto =:= <<"_tcp">> orelse Proto =:= <<"_udp">>;
	_ -> false
    end;
is_dnssd_rr(_ZoneNameLabels, _Name, _Type) -> false.

-ifdef(TEST).

is_dnssd_rr_test_() ->
    Cases =  [{true, <<"_http._tcp.example.com">>, ?DNS_TYPE_PTR},
	      {true, <<"_printer._sub._http._tcp.example.com">>, ?DNS_TYPE_PTR},
	      {true, <<"_services._dns-sd._udp.example.com">>, ?DNS_TYPE_PTR},
	      {false, <<"example.com">>, ?DNS_TYPE_PTR},
	      {true, <<"Test._http._tcp.example.com">>, ?DNS_TYPE_SRV},
	      {false, <<"example.com">>, ?DNS_TYPE_SRV},
	      {false, <<"example.com">>, ?DNS_TYPE_A}],
    CasesRR = [{Bool, #dns_rr{name = Name, type = Type}}
	       || {Bool, Name, Type} <- Cases ],
    CasesDRR = [{Bool, #dnsxd_rr{name = Name, type = Type}}
		|| {Bool, Name, Type} <- Cases ],
    CasesAll = CasesRR ++ CasesDRR,
    [ ?_assertEqual(Result, is_dnssd_rr(<<"example.com">>, RR))
      || {Result, RR} <- CasesAll ].

-endif.

is_dnssd_change(ZoneName, KeyName, {delete, {Name, Type, _Data}}) ->
    is_dnssd_change(ZoneName, KeyName, {delete, {Name, Type}});
is_dnssd_change(_ZoneName, KeyName, {delete, {KeyName, _}}) -> true;
is_dnssd_change(ZoneName, _KeyName, {delete, {Name, Type}}) ->
    is_dnssd_rr(ZoneName, Name, Type);
is_dnssd_change(_ZoneName, KeyName, {delete, KeyName}) -> true;
is_dnssd_change(ZoneName, KeyName, {add, {Name, Type, _TTL, _Data}}) ->
    case Name of
	KeyName -> true;
	_ -> is_dnssd_rr(ZoneName, Name, Type)
    end;
is_dnssd_change(_ZoneName, _KeyName, _Change) -> false.

use_procket() ->
    case dnsxd:get_env(procket) of
	{ok, Props} when is_list(Props) -> proplists:get_bool(enabled, Props);
	_ -> false
    end.

procket_open(IP, Port, Protocol, Type) ->
    {ok, Props} = dnsxd:get_env(procket),
    Progname = proplists:get_value(progname, Props, "procket"),
    Family = case tuple_size(IP) of
		 4 -> inet;
		 8 -> inet6
	     end,
    Opts = [{progname, Progname}, {protocol, Protocol}, {type, Type},
	    {family, Family}],
    case procket:open(Port, Opts) of
	{ok, Fd} = Result ->
	    Parent = self(),
	    Fun = fun() ->
			  process_flag(trap_exit, true),
			  receive {'EXIT', Parent, _} -> ok end,
			  ok = procket:close(Fd)
		  end,
	    spawn_link(Fun),
	    Result;
	Result -> Result
    end.

cancel_timer(Ref) when is_reference(Ref) -> _ = erlang:cancel_timer(Ref), ok;
cancel_timer(_) -> ok.

ip_to_txt(IP)
  when is_tuple(IP) andalso tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8 ->
    case list_to_binary(inet_parse:ntoa(IP)) of
	<<"::FFFF:", Bin/binary>> -> Bin;
	Bin -> Bin
    end.
