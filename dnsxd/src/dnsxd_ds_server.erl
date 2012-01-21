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
-module(dnsxd_ds_server).
-include("dnsxd_internal.hrl").
-behaviour(gen_server).

-define(SERVER, ?MODULE).

-define(TAB_BADZONE, dnsxd_badzone).
-define(TAB_RELOAD, dnsxd_reload).
-define(TAB_RRMAP, dnsxd_rrmap).
-define(TAB_RRNAME, dnsxd_rrname).
-define(TAB_RRSET, dnsxd_rrset).
-define(TAB_TSIG, dnsxd_tsig).
-define(TAB_ZONE, dnsxd_zone).
-define(TAB_LIST, [?TAB_BADZONE, ?TAB_RELOAD, ?TAB_RRNAME, ?TAB_RRMAP,
		   ?TAB_RRSET, ?TAB_TSIG, ?TAB_ZONE]).

-record(state, {reload_ref, reload_pid}).
-record(badzone, {name,
		  attempts = 1,
		  first_attempt = dns:unix_time(),
		  last_attempt = dns:unix_time()}).
-record(reload, {zonename, time}).

%% API
-export([start_link/0, ets_memory/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

%% zone management
-export([load_zone/1, reload_zone/1, delete_zone/1, zone_loaded/1]).

%% querying
-export([find_zone/1, is_dnssec_zone/1, axfr_hosts/1, lookup_rrname/2,
	 is_cut/2, lookup_sets/4, get_set/3, get_all_sets/1, get_key/1,
	 zonename_from_ref/1, get_nsec3_cover/2, get_zone/1, next_serial/1]).

%%%===================================================================
%%% API
%%%===================================================================

start_link() -> gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

load_zone(#dnsxd_zone{} = Zone) -> gen_server:call(?SERVER, {load_zone, Zone}).

reload_zone(#dnsxd_zone{} = Zone) ->
    gen_server:call(?SERVER, {reload_zone, Zone}).

delete_zone(ZoneName) -> gen_server:call(?SERVER, {delete_zone, ZoneName}).

next_serial(ZoneName) when is_binary(ZoneName) ->
    case get_zone_rec(ZoneName) of
	#zone{name = ZoneName, serials = Serials} ->
	    Now = dns:unix_time(),
	    case lists:dropwhile(fun(Serial) -> Serial =< Now end, Serials) of
		[NextSerial|_] -> NextSerial;
		[] -> undefined
	    end;
	_ -> undefined
    end.

find_zone(Name) when is_binary(Name) ->
    case zone_for_name(Name) of
	#zone{} = Ref -> get_current_serial_ref(Ref);
	undefined -> undefined
    end.

zonename_from_ref(#zone_ref{name = Name}) -> Name;
zonename_from_ref(#serial_ref{zone_ref = Ref}) -> zonename_from_ref(Ref);
zonename_from_ref(#rrname_ref{serial_ref = Ref}) -> zonename_from_ref(Ref).

is_dnssec_zone(#serial_ref{zone_ref = Ref}) -> is_dnssec_zone(Ref);
is_dnssec_zone(#zone_ref{name = Name}) ->
    Labels = dns:dname_to_labels(Name),
    undefined =/= ets:lookup_element(?TAB_ZONE, Labels, #zone.nsec3).

axfr_hosts(#serial_ref{zone_ref = ZoneRef}) -> axfr_hosts(ZoneRef);
axfr_hosts(#zone_ref{name = Name}) ->
    Labels = dns:dname_to_labels(Name),
    ets:lookup_element(?TAB_ZONE, Labels, #zone.axfr).

get_key(FQKeyName) ->
    case fqkn_to_key_and_zonename(FQKeyName) of
	undefined -> undefined;
	{KeyName, ZoneName} ->
	    ZoneNameLabels = dns:dname_to_labels(ZoneName),
	    case ets:lookup(?TAB_ZONE, ZoneNameLabels) of
		[#zone{name = ZoneName, ref = Ref}] ->
		    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
		    Keys = ets:lookup_element(?TAB_TSIG, ZoneRef, #tsig.keys),
		    case lists:keyfind(KeyName, #dnsxd_tsig_key.name, Keys) of
			#dnsxd_tsig_key{} = Key -> {ZoneName, Key};
			false -> undefined
		    end;
		[#zone{name = undefined}] -> undefined;
		[] -> undefined
	    end
    end.

fqkn_to_key_and_zonename(FQKeyName) ->
    fqkn_to_key_and_zonename(<<>>, FQKeyName).

fqkn_to_key_and_zonename(KeyName, <<$., ZoneName/binary>>) ->
    {KeyName, ZoneName};
fqkn_to_key_and_zonename(KeyName, <<"\\.", Rest/binary>>) ->
    fqkn_to_key_and_zonename(<<KeyName/binary, "\\.">>, Rest);
fqkn_to_key_and_zonename(KeyName, <<C, Rest/binary>>) ->
    fqkn_to_key_and_zonename(<<KeyName/binary, C>>, Rest);
fqkn_to_key_and_zonename(_, _) -> undefined.

lookup_rrname(#serial_ref{zone_ref = #zone_ref{name = ZoneName}} = Ref, Name) ->
    Tree = ets:lookup_element(?TAB_RRMAP, Ref, #rrmap.tree),
    nametree_lookup(ZoneName, Name, Tree).

is_cut(#serial_ref{} = SerialRef, QName) ->
    AscName = case lookup_rrname(SerialRef, QName) of
		  {found, Name} -> Name;
		  {found_wild, LastName, _Name, _WildName} -> LastName;
		  {no_name, LastName, _Name, _WildName} -> LastName
	      end,
    RRNameRef = #rrname_ref{serial_ref = SerialRef, name = AscName},
    ets:lookup_element(?TAB_RRNAME, RRNameRef, #rrname.cutby) =/= undefined.

get_nsec3_cover(#serial_ref{zone_ref = ZoneRef} = SerialRef, Name) ->
    NSEC3 = ets:lookup_element(?TAB_RRMAP, SerialRef, #rrmap.nsec3),
    case lists:keyfind(Name, #nsec3.name, NSEC3) of
	#nsec3{hashdn = HashedName} ->
	    RRNameRef = #rrname_ref{serial_ref = SerialRef, name = HashedName},
	    hd(get_set(RRNameRef, ?DNS_TYPE_NSEC3));
	false ->
	    Hash = get_nsec3_hash(ZoneRef, Name),
	    do_get_nsec3_cover(SerialRef, Hash, NSEC3 ++ [hd(NSEC3)])
    end.

do_get_nsec3_cover(SerialRef, Hash, [#nsec3{hash = Hash1, hashdn = HashDN},
				     #nsec3{hash = Hash2}|_])
  when Hash > Hash1 andalso Hash < Hash2 ->
    RRNameRef = #rrname_ref{serial_ref = SerialRef, name = HashDN},
    hd(get_set(RRNameRef, ?DNS_TYPE_NSEC3));
do_get_nsec3_cover(SerialRef, Hash, [_|[_|_] = Hashes]) ->
    do_get_nsec3_cover(SerialRef, Hash, Hashes);
do_get_nsec3_cover(SerialRef, _Hash, [#nsec3{hashdn = HashDN}]) ->
    RRNameRef = #rrname_ref{serial_ref = SerialRef, name = HashDN},
    hd(get_set(RRNameRef, ?DNS_TYPE_NSEC3)).

get_nsec3_hash(#zone_ref{name = ZoneName}, Name) ->
    ZoneNameLabels = dns:dname_to_labels(ZoneName),
    #dnsxd_nsec3_param{hash = Hash, salt = Salt, iter = Iter} =
	ets:lookup_element(?TAB_ZONE, ZoneNameLabels, #zone.nsec3),
    dnssec:ih(Hash, Salt, dns:encode_dname(Name), Iter).

get_set(#rrname_ref{name = Name} = RRNameRef, QType) ->
    get_set(#rrset_ref{rrname_ref = RRNameRef, type = QType}, Name);
get_set(#rrset_ref{rrname_ref = RRNameRef, type = ?DNS_TYPE_ANY}, QName) ->
    Types = ets:lookup_element(?TAB_RRNAME, RRNameRef, #rrname.types),
    MatchSpecs = [{#rrset{ref = #rrset_ref{rrname_ref = RRNameRef, type = Type},
			  _ = '_'}, [], ['$_']}
		  || Type <- Types ],
    [ Set#rrset{name = QName} || Set <- ets:select(?TAB_RRSET, MatchSpecs) ];
get_set(#rrset_ref{} = Ref, QName) ->
    [ Set#rrset{name = QName} || Set <- ets:lookup(?TAB_RRSET, Ref) ].

get_set(#serial_ref{} = SerialRef, Name, Type) ->
    NameRef = #rrname_ref{serial_ref = SerialRef,
			  name = dns:dname_to_lower(Name)},
    SetRef = #rrset_ref{rrname_ref = NameRef, type = Type},
    get_set(SetRef, Name).


lookup_cut(#rrname_ref{} = Ref) ->
    ets:lookup_element(?TAB_RRNAME, Ref, #rrname.cutby).

get_all_sets(#serial_ref{} = SerialRef) ->
    SetList = ets:lookup_element(?TAB_RRMAP, SerialRef, #rrmap.sets),
    MatchSpecs = [{#rrset{ref = #rrset_ref{rrname_ref = #rrname_ref{
					     serial_ref = SerialRef,
					     name = Name},
					   type = Type},
			  _ = '_'}, [], ['$_']}
		  || {Name, Types} <- SetList, Type <- Types ],
    ets:select(?TAB_RRSET, MatchSpecs).

lookup_sets(#serial_ref{} = SerialRef, QName, Name, Type) ->
    NameRef = #rrname_ref{serial_ref = SerialRef, name = Name},
    SetRef = #rrset_ref{rrname_ref = NameRef, type = Type},
    case get_set(SetRef, QName) of
	[] when Type =:= ?DNS_TYPE_NS -> nodata;
	[] ->
	    SetRefCname = SetRef#rrset_ref{type = ?DNS_TYPE_CNAME},
	    case get_set(SetRefCname, QName) of
		[] ->
		    case lookup_cut(NameRef) of
			undefined -> nodata;
			CutBy ->
			    CutNameRef = NameRef#rrname_ref{name = CutBy},
			    NS = get_set(CutNameRef, ?DNS_TYPE_NS),
			    DS = get_set(CutNameRef, ?DNS_TYPE_DS),
			    Ad = get_glue(SerialRef, NS),
			    {cut, NS, DS, Ad}
		    end;
		[#rrset{cutby = undefined}|_] = Matches -> {match, Matches};
		[#rrset{cutby = CutBy}|_] ->
		    CutNameRef = NameRef#rrname_ref{name = CutBy},
		    NS = get_set(CutNameRef, ?DNS_TYPE_NS),
		    DS = get_set(CutNameRef, ?DNS_TYPE_DS),
		    Ad = get_glue(SerialRef, NS),
		    {cut, NS, DS, Ad}
	    end;
	[#rrset{cutby = undefined}|_] = Matches -> {match, Matches};
	[#rrset{cutby = CutBy}|_] ->
	    CutNameRef = NameRef#rrname_ref{name = CutBy},
	    NS = get_set(CutNameRef, ?DNS_TYPE_NS),
	    DS = get_set(CutNameRef, ?DNS_TYPE_DS),
	    Ad = get_glue(SerialRef, NS),
	    {cut, NS, DS, Ad}
    end.

get_glue(#serial_ref{} = Ref, [#rrset{}] = NS) -> get_glue(Ref, NS, []).

get_glue(#serial_ref{} = Ref, [#rrset{add_dnames = GlueNames}], Ad)
  when is_list(Ad) -> get_glue(Ref, GlueNames, lists:reverse(Ad));
get_glue(#serial_ref{} = SerialRef, [Name|Names], Ad) ->
    NameRef = #rrname_ref{serial_ref = SerialRef, name = Name},
    Fun = fun(Type, Acc) ->
		  [ Set || Set <- get_set(NameRef, Type),
			   not lists:member(Set, Ad) ] ++ Acc
	  end,
    Ad0 = lists:foldl(Fun, Ad, [?DNS_TYPE_A, ?DNS_TYPE_AAAA]),
    get_glue(SerialRef, Names, Ad0);
get_glue(#serial_ref{}, [], Ad) when is_list(Ad) -> lists:reverse(Ad).

zone_for_name(Name) when is_binary(Name) ->
    zone_for_name(undefined, [], lists:reverse(dns:dname_to_labels(Name))).

zone_for_name(LastZoneEntry, _PrevLabels, []) -> LastZoneEntry;
zone_for_name(LastZoneEntry, PrevLabels, [Label|Labels]) ->
    CurLabels = [Label|PrevLabels],
    case ets:lookup(?TAB_ZONE, CurLabels) of
	[#zone{cuts = 0, name = undefined}] -> LastZoneEntry;
	[#zone{cuts = 0} = ZoneEntry] -> ZoneEntry;
	[#zone{name = undefined}] ->
	    zone_for_name(LastZoneEntry, CurLabels, Labels);
	[#zone{} = ZoneEntry] ->
	    zone_for_name(ZoneEntry, CurLabels, Labels);
	[] -> undefined
    end.

get_zone(Name) when is_binary(Name) ->
    case get_zone_rec(Name) of
	#zone{} = Zone -> get_current_serial_ref(Zone);
	_ -> undefined
    end.

get_zone_rec(Name) when is_binary(Name) ->
    ZoneNameLabels = dns:dname_to_labels(Name),
    case ets:lookup(?TAB_ZONE, ZoneNameLabels) of
	[#zone{soa= #dnsxd_soa_param{}} = Zone] -> Zone;
	_ -> undefined
    end.

zone_loaded(ZoneName) when is_binary(ZoneName) ->
    Labels = dns:dname_to_labels(ZoneName),
    case ets:lookup(?TAB_ZONE, Labels) of
	[#zone{soa = SOA}] -> SOA =/= undefined;
	_ -> false
    end.

ets_memory() ->
    WordSize = erlang:system_info(wordsize),
    Fun = fun(Tab, Acc) ->
		  TabSize = ets:info(Tab, memory) * WordSize,
		  {{Tab, TabSize}, TabSize + Acc}
	  end,
    {TabSizes, Total} = lists:mapfoldl(Fun, 0, ?TAB_LIST),
    [{total, Total}|TabSizes].

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Fun = fun(Tab) ->
		  Opts = [named_table, {keypos, 2}, {read_concurrency, true}],
		  Tab = ets:new(Tab, Opts)
	  end,
    lists:foreach(Fun, ?TAB_LIST),
    State = set_reload_timer(#state{}),
    {ok, State}.

handle_call({load_zone, #dnsxd_zone{name = ZoneName} = Zone}, _From, State) ->
    Reply = case zone_loaded(ZoneName) of
		true -> {error, loaded};
		false -> insert_zone(Zone)
	    end,
    {reply, Reply, State};
handle_call({reload_zone, #dnsxd_zone{} = Zone}, _From, State) ->
    Reply = insert_zone(Zone),
    {reply, Reply, State};
handle_call({delete_zone, ZoneName}, _From, #state{} = State) ->
    Reply = do_delete_zone(ZoneName),
    {reply, Reply, State};
handle_call(Request, _From, State) ->
    ?DNSXD_ERR("Stray call:~n~p~nState:~n~p~n", [Request, State]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?DNSXD_ERR("Stray cast:~n~p~nState:~n~p~n", [Msg, State]),
    {noreply, State}.

handle_info({clean_zone, #zone_ref{} = ZoneRef, Serials}, State) ->
    ok = clean_zone(ZoneRef, Serials),
    {noreply, State};
handle_info(reload_zones, #state{reload_pid = undefined} = State) ->
    Now = dns:unix_time(),
    MatchSpec = [{#reload{zonename = '$1', time = '$2'},
		  [{'<', '$2', Now}], ['$1']}],
    Self = self(),
    NewState = case ets:select(?TAB_RELOAD, MatchSpec) of
		   [] -> set_reload_timer(State);
		   Zones ->
		       [ ets:delete(?TAB_RELOAD, Zone) || Zone <- Zones ],
		       Datastore = dnsxd:datastore(),
		       Fun = fun() ->
				     ok = Datastore:dnsxd_reload_zones(Zones),
				     Self ! {reload_zones_done, self()}
			     end,
		       State#state{reload_pid = spawn_link(Fun)}
	       end,
    {noreply, NewState};
handle_info({reload_zones_done, Pid}, #state{reload_pid = Pid} = State) ->
    NewState = set_reload_timer(State#state{reload_pid = undefined}),
    {noreply, NewState};
handle_info(Info, State) ->
    ?DNSXD_ERR("Stray message:~n~p~nState:~n~p~n", [Info, State]),
    {noreply, State}.

terminate(_Reason, #state{reload_ref = Ref}) ->
    dnsxd_lib:cancel_timer(Ref).

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

set_reload_timer(#state{reload_ref = Ref} = State) ->
    ok = dnsxd_lib:cancel_timer(Ref),
    {ok, NewRef} = timer:send_after(5000, ?SERVER, reload_zones),
    State#state{reload_ref = NewRef}.

do_delete_zone(ZoneName) ->
    ZoneNameLabels = dns:dname_to_labels(ZoneName),
    ets:delete(?TAB_RELOAD, ZoneName),
    case ets:lookup(?TAB_ZONE, ZoneNameLabels) of
	[#zone{ref = Ref, serials = Serials, cuts = Cuts}] ->
	    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
	    ets:delete(?TAB_TSIG, ZoneRef),
	    ok = decrement_zone_entry_cuts(ZoneNameLabels),
	    case Cuts of
		0 -> ets:delete(?TAB_ZONE, ZoneNameLabels);
		Cuts ->
		    NewZone = #zone{labels = ZoneNameLabels, cuts = Cuts - 1},
		    ets:insert(?TAB_ZONE, NewZone)
	    end,
	    ok = schedule_clean_zone(ZoneRef, Serials);
	[] -> ok
    end.

schedule_clean_zone(#zone_ref{} = ZoneRef, Serials) ->
    schedule_clean_zone(ZoneRef, Serials, 0).

schedule_clean_zone(ZoneName, Ref, Serials)
  when is_binary(ZoneName) andalso is_list(Serials)->
    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
    schedule_clean_zone(ZoneRef, Serials, 0);
schedule_clean_zone(#zone_ref{} = ZoneRef, Serials, After)
  when is_integer(After) andalso After >= 0 ->
    _ = erlang:send_after(After, self(), {clean_zone, ZoneRef, Serials}),
    ok.

schedule_clean_zone(ZoneName, Ref, Serials, After) ->
    ZoneRef = #zone_ref{name = ZoneName, ref = Ref},
    schedule_clean_zone(ZoneRef, Serials, After).

clean_zone(ZoneRef, [Serial|Serials]) ->
    SerialRef = #serial_ref{zone_ref = ZoneRef, serial = Serial},
    Fun = fun({Name, Types}) ->
		  RRNameRef = #rrname_ref{serial_ref = SerialRef, name = Name},
		  ets:delete(?TAB_RRNAME, RRNameRef),
		  [ ets:delete(?TAB_RRSET, #rrset_ref{rrname_ref = RRNameRef,
						      type = Type})
		    || Type <- Types ]
	  end,
    [#rrmap{sets = Sets}] = ets:lookup(?TAB_RRMAP, SerialRef),
    true = ets:delete(?TAB_RRMAP, SerialRef),
    lists:foreach(Fun, Sets),
    clean_zone(ZoneRef, Serials);
clean_zone(_ZoneRef, []) -> ok.

insert_zone(#dnsxd_zone{name = ZoneName} = Zone) when is_binary(ZoneName) ->
    ets:delete(?TAB_RELOAD, ZoneName),
    FailedPreviously = ets:member(?TAB_BADZONE, ZoneName),
    TempTab = ets:new(dnsxd_tmp_lz, [public, duplicate_bag]),
    Ref = make_ref(),
    case dnsxd_zone:prepare(TempTab, Ref, #dnsxd_zone{} = Zone) of
	{ok, Serials, SOA, NSEC3, AXFR} ->
	    if FailedPreviously -> ets:delete(?TAB_BADZONE, ZoneName);
	       true -> ok end,
	    ok = insert_from_temp_tab(TempTab),
	    true = ets:delete(TempTab),
	    ok = add_to_zone_tab(ZoneName, Ref, Serials, AXFR, SOA, NSEC3),
	    ok = add_reload_entry(ZoneName, Serials),
	    ok = dnsxd_llq_manager:zone_changed(ZoneName);
	{error, Reason} ->
	    true = ets:delete(TempTab),
	    if FailedPreviously ->
		    Attempts = ets:lookup_element(?TAB_BADZONE, ZoneName,
						  #badzone.attempts),
		    Updates = [{#badzone.last_attempt, dns:unix_time()},
			       {#badzone.attempts, Attempts + 1}],
		    ets:update_element(?TAB_BADZONE, ZoneName, Updates);
	       true -> ets:insert(?TAB_BADZONE, #badzone{name = ZoneName})
	    end,
	    ?DNSXD_INFO("Failed to insert zone ~s:~n~p", [ZoneName, Reason]),
	    {error, bad_zone}
    end.

add_to_zone_tab(ZoneName, Ref, Serials, AXFR, #dnsxd_soa_param{} = SOA, NSEC3)
  when is_record(NSEC3, dnsxd_nsec3_param) orelse NSEC3 =:= undefined ->
    ZoneNameLabels = dns:dname_to_labels(ZoneName),
    NewZone = #zone{labels = ZoneNameLabels,
		    name = ZoneName,
		    soa = SOA,
		    ref = Ref,
		    serials = Serials,
		    axfr = AXFR,
		    nsec3 = NSEC3},
    case ets:lookup(?TAB_ZONE, ZoneNameLabels) of
	[#zone{name = undefined, cuts = Cuts}] ->
	    true = ets:insert(?TAB_ZONE, NewZone#zone{cuts = Cuts}),
	    ok = increment_zone_entry_cut(ZoneNameLabels);
	[#zone{ref = OldRef, serials = OldSerials, cuts = Cuts}] ->
	    ok = schedule_clean_zone(ZoneName, OldRef, OldSerials, 1000),
	    true = ets:insert(?TAB_ZONE, NewZone#zone{cuts = Cuts}),
	    ok;
	[] ->
	    true = ets:insert(?TAB_ZONE, NewZone),
	    ok = increment_zone_entry_cut(ZoneNameLabels)
    end.

increment_zone_entry_cut([_|Labels]) ->
    case ets:member(?TAB_ZONE, Labels) of
	true -> _ = ets:update_counter(?TAB_ZONE, Labels, {#zone.cuts, 1});
	false -> true = ets:insert(?TAB_ZONE, #zone{labels = Labels, cuts = 1})
    end,
    increment_zone_entry_cut(Labels);
increment_zone_entry_cut([]) -> ok.

decrement_zone_entry_cuts([_|Labels]) ->
    case ets:update_counter(?TAB_ZONE, Labels, {#zone.cuts, -1}) of
	0 -> ets:delete(?TAB_ZONE, Labels);
	_ -> ok
    end,
    decrement_zone_entry_cuts(Labels);
decrement_zone_entry_cuts([]) -> ok.

add_reload_entry(ZoneName, Serials) ->
    Now = dns:unix_time(),
    case lists:reverse(Serials) of
	[Reload|_] when Reload > Now ->
	    Entry = #reload{zonename = ZoneName, time = Reload},
	    ets:insert(?TAB_RELOAD, Entry),
	    ok;
	_ -> ok
    end.

insert_from_temp_tab(TempTab) ->
    case ets:select(TempTab, [{'_',[],['$_']}], 10) of
	{Recs, Cont} ->
	    [ ets:insert(tab(Rec), Rec) || Rec <- Recs ],
	    insert_from_temp_tab_cont(Cont);
	'$end_of_table' -> ok
    end.

insert_from_temp_tab_cont(Cont) ->
    case ets:select(Cont) of
	{Recs, NewCont} ->
	    [ ets:insert(tab(Rec), Rec) || Rec <- Recs ],
	    insert_from_temp_tab_cont(NewCont);
	'$end_of_table' -> ok
    end.

nametree_lookup(ZoneName, ZoneName, _Tree) -> {found, ZoneName};
nametree_lookup(ZoneName, Name, Tree) ->
    UQ = strip_zonename(Name, ZoneName),
    Labels = lists:reverse(dns:dname_to_labels(UQ)),
    do_nametree_lookup(ZoneName, Name, Labels, Tree).

do_nametree_lookup(LastName, QName, [Label|Labels], Tree) ->
    case gb_trees:lookup(Label, Tree) of
	{value, {QName, _Wild, _Subtree}} -> {found, QName};
	{value, {NewName, _Wild, SubTree}} ->
	    do_nametree_lookup(NewName, QName, Labels, SubTree);
	none ->
	    Name = <<(dns:escape_label(Label))/binary, $., LastName/binary>>,
	    WildName = <<"*.", LastName/binary>>,
	    case gb_trees:lookup(<<$*>>, Tree) of
		{value, {WildName, true, _SubTree}} ->
		    {found_wild, LastName, Name, WildName};
		_ ->
		    {no_name, LastName, Name, WildName}
	    end
    end.

strip_zonename(Name, ZoneName) ->
    ZoneNameSize = byte_size(ZoneName),
    NameSize = byte_size(Name),
    UQSize = NameSize - ZoneNameSize - 1,
    <<UQ:UQSize/binary, $., ZoneName/binary>> = Name,
    UQ.

zone_ref(#zone{name = Name, ref = Ref}) -> #zone_ref{name = Name, ref = Ref}.

get_current_serial_ref(#zone{} = Zone) -> get_serial_ref(Zone, dns:unix_time()).

get_serial_ref(#zone{serials = Serials} = Zone, Now) ->
    ZoneRef = zone_ref(Zone),
    get_serial_ref(ZoneRef, Now, Serials).

get_serial_ref(ZoneRef, Now, [Now|_]) ->
    #serial_ref{zone_ref = ZoneRef, serial = Now};
get_serial_ref(ZoneRef, Now, [Cur,Next|_]) when Now < Next ->
    #serial_ref{zone_ref = ZoneRef, serial = Cur};
get_serial_ref(ZoneRef, Now, [_|[_|_] = Serials]) ->
    get_serial_ref(ZoneRef, Now, Serials);
get_serial_ref(ZoneRef, _Now, [Serial]) ->
    #serial_ref{zone_ref = ZoneRef, serial = Serial}.

tab(#rrmap{}) -> ?TAB_RRMAP;
tab(#rrname{}) -> ?TAB_RRNAME;
tab(#rrset{}) -> ?TAB_RRSET;
tab(#tsig{}) -> ?TAB_TSIG;
tab(#zone{}) -> ?TAB_ZONE.
