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
-module(dnsxd_op_query).
-include("dnsxd_internal.hrl").

%% API
-export([handle/2]).

%%%===================================================================
%%% API
%%%===================================================================

handle(MsgCtx, #dns_message{qc = 1, questions = [Query]} = Msg) ->
    DoDNSSEC = do_dnssec(Msg),
    Props = answer(Query, DoDNSSEC),
    dnsxd_op_ctx:reply(MsgCtx, Msg, Props).

do_dnssec(#dns_message{additional=[#dns_optrr{dnssec = DNSSEC}|_]}) -> DNSSEC;
do_dnssec(#dns_message{}) -> false.

answer(#dns_query{name = QName, type = Type}, DoDNSSEC) ->
    Name = dns:dname_to_lower(QName),
    case dnsxd_ds_server:find_zone(Name) of
	undefined -> [{rc, ?DNS_RCODE_REFUSED}];
	ZoneRef ->
	    DNSSEC = DoDNSSEC andalso dnsxd_ds_server:is_dnssec_zone(ZoneRef),
	    Props = orddict:from_list([{aa, true}, {ad, []}, {an, []}, {au, []},
				       {any, ?DNS_TYPE_ANY =:= Type},
				       {dnssec, DNSSEC}, {followed, []},
				       {rc, ?DNS_RCODE_NXDOMAIN}]),
	    answer(QName, Name, Type, ZoneRef, Props)
    end.

answer(QName, Name, Type, Ref, Props) ->
    DNSSEC = orddict:fetch(dnssec, Props),
    Followed = [] =/= orddict:fetch(followed, Props),
    case dnsxd_ds_server:lookup_rrname(Ref, Name) of
	{found, Name} ->
	    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
	    case dnsxd_ds_server:lookup_sets(Ref, QName, Name, Type) of
		nodata when Followed -> Props;
		nodata ->
		    Props1 = append_au_soa(Ref, Props0),
		    if DNSSEC -> append_nsec3_cover(Ref, Name, Props1);
				true -> Props1 end;
		{match, Matches} ->
		    case handle_match(Ref, Type, Matches, Props0) of
			{done, Props1} -> Props1;
			{follow, NewQName, Props1} ->
			    NewName = dns:dname_to_lower(NewQName),
			    answer(NewQName, NewName, Type, Ref, Props1)
		    end;
		_ when Followed -> Props;
		{cut, NS, DS, AddSets} ->
		    handle_cut(Ref, DNSSEC, NS, DS, AddSets, Props0)
	    end;
	{found_wild, LastName, PlainName, WildName} ->
	    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
	    case dnsxd_ds_server:lookup_sets(Ref, QName, WildName, Type) of
		nodata ->
		    Props1 = append_au_soa(Ref, Props0),
		    Cover = [LastName, PlainName, WildName],
		    if DNSSEC ->
			    append_nsec3_cover(Ref, Cover, Props1);
		       true -> Props1 end;
		{match, Matches} ->
		    case handle_match(Ref, Type, Matches, Props0) of
			{done, Props1} when DNSSEC ->
			    append_nsec3_cover(Ref, PlainName, Props1);
			{done, Props1} -> Props1;
			{follow, NewQName, Props1} when DNSSEC ->
			    Props2 = append_nsec3_cover(Ref, PlainName, Props1),
			    NewName = dns:dname_to_lower(NewQName),
			    answer(NewQName, NewName, Type, Ref, Props2);
			{follow, NewQName, Props1} ->
			    NewName = dns:dname_to_lower(NewQName),
			    answer(NewQName, NewName, Type, Ref, Props1)
		    end;
		_ when Followed -> Props;
		{cut, NS, DS, AddSets} ->
		    handle_cut(Ref, DNSSEC, NS, DS, AddSets, Props0)
	    end;
	_ when Followed -> Props;
	{no_name, LastName, PlainName, WildName} ->
	    case dnsxd_ds_server:lookup_sets(Ref, LastName, LastName, Type) of
		{cut, NS, DS, AddSets} ->
		    Props0 = orddict:store(rc, ?DNS_RCODE_NOERROR, Props),
		    Props1 = handle_cut(Ref, DNSSEC, NS, DS, AddSets, Props0),
		    if DNSSEC ->
			    case parent(LastName) of
				undefined -> Props1;
				ParentName ->
				    append_nsec3_cover(Ref, ParentName, Props1)
			    end;
		       true -> Props1
		    end;
		_ when DNSSEC ->
		    Props0 = append_au_soa(Ref, Props),
		    Cover = [PlainName, LastName, WildName],
		    append_nsec3_cover(Ref, Cover, Props0);
		_ -> append_au_soa(Ref, Props)
	    end
    end.

handle_match(Ref, Type, [#rrset{type = ?DNS_TYPE_CNAME = Type} = Set], Props) ->
    Props0 = append_an_ad(Ref, Set, Props),
    {done, append_au_ns(Ref, Props0)};
handle_match(Ref, _Type, [#rrset{type = ?DNS_TYPE_CNAME,
				 add_dnames = [NewQName]} = Set], Props) ->
    Props0 = append_an_ad(Ref, Set, Props),
    Props1 = append_au_ns(Ref, Props0),
    case follow_cname(Ref, Props1, NewQName) of
	{Props2, true} -> {follow, NewQName, Props2};
	{Props2, false} -> {done, Props2}
    end;
handle_match(Ref, _Type, Sets, Props) when is_list(Sets) ->
    Props0 = append_an_ad(Ref, Sets, Props),
    {done, append_au_ns(Ref, Props0)}.

handle_cut(Ref, true, [#rrset{name = Name} = NS], DS, Add, Props) ->
    Props0 = append(au, NS, Props),
    Props1 = append(au, DS, Props0),
    Props2 = append_nsec3_cover(Ref, Name, Props1),
    Props3 = append(ad, Add, Props2),
    orddict:store(aa, false, Props3);
handle_cut(_Ref, false, NS, DS, Add, Props) ->
    Add0 = case orddict:fetch(any, Props) of
	       true -> lists:keysort(#rrset.type, DS ++ Add);
	       false -> Add
	   end,
    Props0 = orddict:store(aa, false, Props),
    Props1 = append(au, NS, Props0),
    append(ad, Add0, Props1).

append(Key, #rrset{} = Set, Props) -> orddict:append(Key, Set, Props);
append(Key, Sets, Props) when is_list(Sets) ->
    orddict:append_list(Key, Sets, Props).

append_an_ad(Ref, #rrset{} = Set, Props) ->
    append_an_ad(Ref, [Set], Props);
append_an_ad(Ref, Sets, Props) ->
    Props0 = append(an, Sets, Props),
    append_ad_from_sets(Ref, Sets, Props0).

append_ad_from_sets(Ref, Sets, Props) ->
    Existing = lists:foldl(
	fun(Key, Acc) ->
		SetsTmp = orddict:fetch(Key, Props),
		sets:union(Acc, sets:from_list(
				  [ {dns:dname_to_lower(N), T}
				    || #rrset{name = N, type = T} <- SetsTmp ]))
	end, sets:new(), [an, ad, au]),
    FollowTypes = [ ?DNS_TYPE_MX, ?DNS_TYPE_NS, ?DNS_TYPE_PTR, ?DNS_TYPE_SRV ],
    Follow0 = [ {Name, Type} || #rrset{add_dnames = Names, type = Type} <- Sets,
				Name <- Names ],
    Follow1 = lists:foldl(
		fun({Name, Type}, Acc) ->
			Key = {dns:dname_to_lower(Name), Type},
			IgnoreType = not lists:member(Type, FollowTypes),
			InExisting = sets:is_element(Key, Existing),
			InAcc = dict:is_key(Key, Acc),
			if IgnoreType orelse InExisting orelse InAcc -> Acc;
			   true -> dict:store(Key, Name, Acc) end
		end, dict:new(), Follow0),
    Follow2 = [ {Type, Name} || {{_, Type}, Name} <- dict:to_list(Follow1) ],
    do_append_ad_from_sets(Ref, Props, Follow2).

do_append_ad_from_sets(Ref, Props, [{SrcType, Name}|Follow]) ->
    TargetTypes = case SrcType of
		      ?DNS_TYPE_PTR -> [?DNS_TYPE_DS,
					?DNS_TYPE_SRV,
					?DNS_TYPE_TXT];
		      _ -> [?DNS_TYPE_A, ?DNS_TYPE_AAAA]
		  end,
    Fun = fun(Type, PropsTmp) ->
		  Matches = dnsxd_ds_server:get_set(Ref, Name, Type),
		  append(ad, Matches, PropsTmp)
	  end,
    Props0 = lists:foldl(Fun, Props, TargetTypes),
    do_append_ad_from_sets(Ref, Props0, Follow);
do_append_ad_from_sets(_Ref, Props, []) -> Props.

append_au_ns(Ref, Props) ->
    case orddict:is_key(append_au_ns, Props) of
	true -> Props;
	false ->
	    Props0 = orddict:store(append_au_ns, true, Props),
	    ZoneName = dnsxd_ds_server:zonename_from_ref(Ref),
	    NS = dnsxd_ds_server:get_set(Ref, ZoneName, ?DNS_TYPE_NS),
	    An = orddict:fetch(an, Props0),
	    case lists:member(NS, An) of
		true -> Props0;
		false -> append(au, NS, Props0)
	    end
    end.

append_au_soa(Ref, Props) ->
    ZoneName = dnsxd_ds_server:zonename_from_ref(Ref),
    SOA = dnsxd_ds_server:get_set(Ref, ZoneName, ?DNS_TYPE_SOA),
    append(au, SOA, Props).

append_nsec3_cover(Ref, Name, Props) when is_binary(Name) ->
    append_nsec3_cover(Ref, [Name], Props, []);
append_nsec3_cover(Ref, Names, Props) when is_list(Names) ->
    append_nsec3_cover(Ref, lists:reverse(Names), Props, []).

append_nsec3_cover(Ref, [Name|Names], Props, Collected) ->
    Cover = dnsxd_ds_server:get_nsec3_cover(Ref, Name),
    case lists:member(Cover, Collected) of
	true -> append_nsec3_cover(Ref, Names, Props, Collected);
	false ->
	    Collected0 = [Cover|Collected],
	    append_nsec3_cover(Ref, Names, Props, Collected0)
    end;
append_nsec3_cover(_Ref, [], Props, Collected) ->
    orddict:append_list(au, Collected, Props).

follow_cname(ZoneRef, Props, NameM) ->
    Name = dns:dname_to_lower(NameM),
    Followed = orddict:fetch(followed, Props),
    case lists:member(Name, Followed) of
	true -> throw({cname_loop, Name});
	false ->
	    Props0 = orddict:append(followed, Name, Props),
	    {Props0, ZoneRef =:= dnsxd_ds_server:find_zone(Name)}
    end.

parent(<<$., Name/binary>>) -> Name;
parent(<<"\\.", Name/binary>>) -> parent(Name);
parent(<<_, Name/binary>>) -> parent(Name);
parent(<<>>) -> undefined.
