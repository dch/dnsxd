-module(dnsxd_ct).
-include("dnsxd_ct.hrl").

-export([dnsxd_allow_axfr/2]).
-export([testcase_init/1, testcase_end/1]).
-export([gen_ms_rr/2, send/2, match_message/2, match_response/3]).

-define(SERVER_PORT, 5533).

dnsxd_allow_axfr(_,_) ->
    {ok, Allow} = dnsxd:get_env(ct_allow_axfr),
    Allow.

testcase_init(Config) ->
    AllowAXFR = not proplists:get_bool(axfr_disabled, Config),
    Transport = proplists:get_value(transport, Config, udp),
    Config0 = ?update_pl(transport, Transport, Config),
    IPStr = proplists:get_value(ip, Config0, "::1"),
    ok = application:load(dnsxd),
    lists:foreach(fun({K, V}) -> ok = application:set_env(dnsxd, K, V) end,
		  [{datastore_mod, ?MODULE},
		   {log_mod, ?MODULE},
		   {ct_allow_axfr, AllowAXFR},
		   {interfaces, [{IPStr, ?SERVER_PORT, Transport}]}]),
    ok = dnsxd:start(),
    {ok, IP} = inet_parse:address(IPStr),
    Config1 = listen(?update_pl(ip, IP, Config0)),
    {Config2, Zone} = generate_zone(Config1),
    ok = dnsxd:reload_zone(Zone),
    Config2.

testcase_end(Config) ->
    ok = dnsxd:stop(),
    ok = application:unload(dnsxd),
    ok = close(Config).

listen(Config) ->
    Transport = proplists:get_value(transport, Config),
    IP = proplists:get_value(ip, Config),
    Opts = [binary, {active, false}, {ip, IP}],
    {ok, Socket} = case Transport of
		       udp -> gen_udp:open(0, Opts);
		       tcp ->
			   gen_tcp:connect(IP, ?SERVER_PORT, [{packet, 2}|Opts])
		   end,
    [{socket, Socket}|Config].

send(Config, #dns_message{} = Msg) ->
    send(Config, dns:encode_message(Msg));
send(Config, Msg) when is_binary(Msg) ->
    IP = proplists:get_value(ip, Config),
    Socket = proplists:get_value(socket, Config),
    case proplists:get_value(transport, Config) of
	udp -> gen_udp:send(Socket, IP, ?SERVER_PORT, Msg);
	tcp -> gen_tcp:send(Socket, Msg)
    end.

recv(Config) ->
    Timeout = proplists:get_value(timeout, Config, 2000),
    Socket = proplists:get_value(socket, Config),
    case proplists:get_value(transport, Config) of
	udp ->
	    case gen_udp:recv(Socket, 0, Timeout) of
		{ok, {_IP, _Port, Bin}} -> {ok, Bin};
		Other -> Other
	    end;
	tcp -> gen_tcp:recv(Socket, 0, Timeout)
    end.

close(Config) ->
    Socket = proplists:get_value(socket, Config),
    case proplists:get_value(transport, Config) of
	udp -> gen_udp:close(Socket);
	tcp -> gen_tcp:close(Socket)
    end.

generate_zone(Config) ->
    Now = proplists:get_value(now, Config, dns:unix_time()),
    Domain = proplists:get_value(domain, Config, <<"example">>),
    RR = proplists:get_value(rr, Config, []),
    SOAOpts = proplists:get_value(soa, Config, []),
    SOAParam = #dnsxd_soa_param{
      mname = proplists:get_value(mname, SOAOpts, <<"mname.", Domain/binary>>),
      rname = proplists:get_value(rname, SOAOpts, <<"rname.", Domain/binary>>),
      refresh = proplists:get_value(refresh, SOAOpts, 3600),
      retry = proplists:get_value(retry, SOAOpts, 300),
      expire = proplists:get_value(expire, SOAOpts, 3600000),
      minimum = proplists:get_value(minimum, SOAOpts, 3600)
     },
    DNSSECSigLife = proplists:get_value(dnssec_siglife, Config, 1250000),
    NSEC3Opts = proplists:get_value(nsec3, Config, []),
    NSEC3Param = #dnsxd_nsec3_param{
      hash = proplists:get_value(hash, NSEC3Opts, 1),
      salt = proplists:get_value(salt, NSEC3Opts, <<"aabbccdd">>),
      iter = proplists:get_value(iter, NSEC3Opts, 12)
     },
    Config0 = ?update_pl(now, Now, ?update_pl(domain, Domain, Config)),
    Zone = #dnsxd_zone{name = Domain,
		       enabled = true,
		       rr = prepare_rr(RR, Config0),
		       serials = undefined,
		       tsig_keys = [],
		       soa_param = SOAParam,
		       dnssec_enabled = false,
		       dnssec_keys = [],
		       dnssec_siglife = 0,
		       nsec3 = undefined},
    Zone0 = case proplists:get_bool(dnssec, Config0) of
		true ->
		    Zone#dnsxd_zone{
		      dnssec_enabled = true,
		      dnssec_keys = [ new_dnssec_rsa_key(Now, Bool)
				      || Bool <- [true, false] ],
		      dnssec_siglife = DNSSECSigLife,
		      nsec3 = NSEC3Param
		     };
		false -> Zone
	    end,
    {Config0, Zone0}.

prepare_rr(#dnsxd_rr{incept = undefined} = RR, Config) ->
    Now = proplists:get_value(now, Config),
    prepare_rr(RR#dnsxd_rr{incept = Now}, Config);
prepare_rr(#dnsxd_rr{class = undefined} = RR, Config) ->
    prepare_rr(RR#dnsxd_rr{class = ?DNS_CLASS_IN}, Config);
prepare_rr(#dnsxd_rr{ttl = undefined} = RR, Config) ->
    TTL = proplists:get_value(default_ttl, Config, 3600),
    prepare_rr(RR#dnsxd_rr{ttl = TTL}, Config);
prepare_rr(#dnsxd_rr{name = undefined} = RR, Config) ->
    Domain = proplists:get_value(domain, Config),
    prepare_rr(RR#dnsxd_rr{name = Domain}, Config);
prepare_rr(#dnsxd_rr{type = undefined, data = Data} = RR, Config)
  when is_tuple(Data) ->
    Type = dns_record_info:type_for_atom(element(1, Data)),
    prepare_rr(RR#dnsxd_rr{type = Type}, Config);
prepare_rr(#dnsxd_rr{} = RR, _Config) -> RR;
prepare_rr(RRs, Config) when is_list(RRs) ->
    [ prepare_rr(RR, Config) || RR <- RRs ].

new_dnssec_rsa_key(Now, KSK) ->
    ok = dnsxd_lib:ensure_apps_started([cutkey]),
    Bits = if KSK -> 1024; true -> 512 end,
    {ok, [<<_:32, _E/binary>>,
	  <<_:32, _N/binary>>,
	  <<_:32, _D/binary>>] = Key} = cutkey:rsa(Bits, 65537),
    Incept = Now,
    Expire = Incept + (365 * 24 * 60 * 60),
    Id = <<$k, (if KSK -> $a; true -> $b end)>>,
    #dnsxd_dnssec_key{id = Id,
		      incept = Incept,
		      expire = Expire,
		      alg = ?DNS_ALG_NSEC3RSASHA1,
		      ksk = KSK,
		      key = Key,
		      keytag = undefined}.


match_response(Config, Q, Spec) ->
    ok = send(Config, Q),
    match_message(Config, Spec).

match_message(Config, Spec) ->
    case recv(Config) of
	{ok, Bin} ->
	    case compare_response(Spec, Bin) of
		true -> true;
		{match, Result} -> Result;
		{nomatch, Result} -> {failed, Result}
	    end;
	Other -> {failed, Other}
    end.

gen_ms_rr(Name, Type) when is_binary(Name) andalso is_integer(Type) ->
    #dns_rr{name = Name, type = Type, _ = '_'};
gen_ms_rr(Name, Type) when is_integer(Type) -> gen_ms_rr(Name, [Type]);
gen_ms_rr(Name, Type) when is_binary(Name) -> gen_ms_rr([Name], Type);
gen_ms_rr(Names, Types) when is_list(Names) andalso is_list(Types) ->
    [ gen_ms_rr(Name, Type) || Name <- Names, Type <- Types ].

compare_response(Spec, Bin) when is_binary(Bin) ->
    Decoded = (catch dns:decode_message(Bin)),
    case match_spec(Spec, Decoded) of
	true -> true;
	false ->
	    Diff = case is_record(Decoded, dns_message) of
		       true -> [{diff, compare_response_diff(Spec, Decoded)}];
		       false -> []
		   end,
	    Result = [{spec, Spec}, {resp, Decoded}|Diff],
	    {nomatch, Result};
	Other -> Other
    end.

compare_response_diff(#dns_message{} = S, #dns_message{} = D) ->
    Fields = record_info(fields, dns_message),
    Values = fun(Msg) -> tl(tuple_to_list(Msg)) end,
    SPairs = [ P || {_K, V} = P <- lists:zip(Fields, Values(S)), V =/= '_'],
    MPairs = lists:zip(Fields, Values(D)),
    lists:foldr(fun({K, V} = Pair, Acc) ->
			case lists:keyfind(K, 1, SPairs) of
			    false -> Acc;
			    Pair -> Acc;
			    {K, SV} when is_list(V) andalso is_list(SV) ->
				case compare_response_diff(SV, V) of
				    [] -> Acc;
				    Diff -> [{K, Diff}|Acc]
				end;
			    {K, SV} -> [{K, SV, V}|Acc]
			end
		end, [], MPairs);
compare_response_diff(A, B) when is_list(A) andalso is_list(B) ->
    compare_response_diff(A, B, []).

compare_response_diff([T|A], [T|B], R) -> compare_response_diff(A, B, R);
compare_response_diff([A|ARest], [B|BRest], R) ->
    NewR = case match_spec(A, B) of
	       true -> R;
	       false -> [{A,B}|R];
	       {match, _} -> R
	   end,
    compare_response_diff(ARest, BRest, NewR);
compare_response_diff([], [], R) -> lists:reverse(R);
compare_response_diff([] = A, [_|_] = B, R) ->
    compare_response_diff(A, [], [{'+', B}|R]);
compare_response_diff([_|_] = A, [] = B, R) ->
    compare_response_diff([], B, [{'-', A}|R]).

match_spec(Spec, Term) ->
    MatchSpec = ets:match_spec_compile([{Spec, [], ['$$']}]),
    case ets:match_spec_run([Term], MatchSpec) of
	[] -> false;
	[[]] -> true;
	[X] -> {match, X}
    end.
