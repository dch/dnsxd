-module(rfc5155_SUITE).
-include("dnsxd_ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([name_error/1, no_data/1, no_data_empty_nonterminal/1, referral_1/1,
	 referral_2/1, wildcard_expansion/1, wildcard_no_data/1,
	 ds_child_zone_no_data_error/1]).

all() -> ?arity1_exports.

rr(Config) ->
    RR = [#dnsxd_rr{data = #dns_rrdata_ns{dname = <<"ns1.example">>}},
	  #dnsxd_rr{data = #dns_rrdata_ns{dname = <<"ns2.example">>}},
	  #dnsxd_rr{data = #dns_rrdata_mx{preference = 1,
					  exchange = <<"xx.example">>}},
	  #dnsxd_rr{name = <<"2t7b4g4vsa5smi47k61mv5bv1a22bojr.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,127}}},
	  #dnsxd_rr{name = <<"a.example">>,
		    data = #dns_rrdata_ns{dname = <<"ns1.example">>}},
	  #dnsxd_rr{name = <<"a.example">>,
		     data = #dns_rrdata_ns{dname = <<"ns2.example">>}},
	  #dnsxd_rr{name = <<"a.example">>,
		    data = #dns_rrdata_ds{
		      keytag = 58470,
		      alg = 1,
		      digest_type = 1,
		      digest = <<48,121,241,89,62,186,214,220,18,30,32,42,139,118,106,106,72,55,32,108>>
		      }},
	  #dnsxd_rr{name = <<"ns1.a.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,5}}},
	  #dnsxd_rr{name = <<"ns2.a.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,6}}},
	  #dnsxd_rr{name = <<"ai.example">>,
		     data = #dns_rrdata_a{ip = {192,0,2,9}}},
	  #dnsxd_rr{name = <<"ai.example">>,
		    data = #dns_rrdata_hinfo{cpu = <<"KLH-10">>,
					     os = <<"ITS">>}},
	  #dnsxd_rr{name = <<"ai.example">>,
		    data = #dns_rrdata_aaaa{
		      ip = {8193,3512,0,0,0,0,3840,47785}}},
	   #dnsxd_rr{name = <<"c.example">>,
		     data = #dns_rrdata_ns{dname = <<"ns1.c.example">>}},
	  #dnsxd_rr{name = <<"c.example">>,
		    data = #dns_rrdata_ns{dname = <<"ns2.c.example">>}},
	  #dnsxd_rr{name = <<"ns1.c.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,7}}},
	  #dnsxd_rr{name = <<"ns2.c.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,8}}},
	  #dnsxd_rr{name = <<"ns1.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,1}}},
	  #dnsxd_rr{name = <<"ns2.example">>,
		     data = #dns_rrdata_a{ip = {192,0,2,2}}},
	  #dnsxd_rr{name = <<"*.w.example">>,
		    data = #dns_rrdata_mx{preference = 1,
					  exchange = <<"ai.example">>}},
	  #dnsxd_rr{name = <<"x.w.example">>,
		    data = #dns_rrdata_mx{preference = 1,
					  exchange = <<"xx.example">>}},
	  #dnsxd_rr{name = <<"x.y.w.example">>,
		    data = #dns_rrdata_mx{preference = 1,
					  exchange = <<"xx.example">>}},
	  #dnsxd_rr{name = <<"xx.example">>,
		    data = #dns_rrdata_a{ip = {192,0,2,10}}},
	  #dnsxd_rr{name = <<"xx.example">>,
		    data = #dns_rrdata_hinfo{cpu = <<"KLH-10">>,
					     os = <<"TOPS-20">>}},
	  #dnsxd_rr{name = <<"xx.example">>,
		    data = #dns_rrdata_aaaa{
		      ip = {8193,3512,0,0,0,0,3840,47786}}}],
    [{rr, RR}|Config].

init_per_testcase(_TestCase, Config) ->
    ?testcase_init(rr([{dnssec, true}|Config])).

end_per_testcase(_TestCase, Config) -> ok = ?testcase_end(Config).

name_error(Config) ->
    Query = #dns_query{name = <<"a.c.x.w.example">>, type = ?DNS_TYPE_SOA},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    SOA = ?gen_ms_rr(<<"example">>, [?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG]),
    NSEC3 = gen_nsec3_ms_rr([{<<"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example">>,
			      <<23,78,178,64,159,226,139,203,72,135,161,131,111,
				149,127,10,132,37,226,123>>,
			     [?DNS_TYPE_MX, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_NS,
			      ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC3PARAM,
			      ?DNS_TYPE_RRSIG]},
			     {<<"b4um86eghhds6nea196smvmlo4ors995.example">>,
			      %% RFC says gjeqe526plbf1g8mklp59enfd789njgi or
			      %% <<132,221,167,20,70,205,86,240,193,22,165,114,
			      %%   84,186,239,105,208,155,206,18>>,
			      %% however injecting _dnsxd-ds records causes
			      %% the order to differ.
			      <<105,118,243,4,59,60,21,168,3,208,197,62,175,135,
				180,146,73,42,120,152>>,
			     [?DNS_TYPE_MX, ?DNS_TYPE_RRSIG]},
			     {<<"35mthgpgcu1qg68fab165klnsnk3dpvl.example">>,
			      <<89,61,100,25,208,140,91,195,93,202,10,77,203,
				126,213,193,49,190,37,37>>,
			      [?DNS_TYPE_NS, ?DNS_TYPE_DS, ?DNS_TYPE_RRSIG]}]),
    Authority = SOA ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      auc = 8,
      adc = 1,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

no_data(Config) ->
    Query = #dns_query{name = <<"ns1.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    SOA = ?gen_ms_rr(<<"example">>, [?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG]),
    NSEC3 = gen_nsec3_ms_rr(<<"2t7b4g4vsa5smi47k61mv5bv1a22bojr.example">>,
			    <<23,243,223,23,178,178,173,174,246,21,37,125,228,
			      210,2,11,128,172,108,124>>,
			    [?DNS_TYPE_A, ?DNS_TYPE_RRSIG]),
    Authority = SOA ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id, qc = 1, anc = 0, auc = 4, adc = 1,
      qr = true,
      aa = true,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

no_data_empty_nonterminal(Config) ->
    Query = #dns_query{name = <<"y.w.example">>, type = ?DNS_TYPE_A},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    SOA = ?gen_ms_rr(<<"example">>, [?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG]),
    NSEC3 = gen_nsec3_ms_rr(<<"ji6neoaepv8b5o6k4ev33abha8ht9fgc.example">>,
			    <<162,60,215,91,249,12,196,243,186,6,155,151,158,4,
			      255,200,238,137,21,17>>, []),
    Authority = SOA ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      qc = 1,
      anc = 0,
      auc = 4,
      adc = 1,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

referral_1(Config) ->
    Query = #dns_query{name = <<"c.example">>, type = ?DNS_TYPE_NS},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    NS = ?gen_ms_rr(<<"c.example">>, [?DNS_TYPE_NS, ?DNS_TYPE_NS]),
    NSEC3 = gen_nsec3_ms_rr(<<"35mthgpgcu1qg68fab165klnsnk3dpvl.example">>,
			    <<89,61,100,25,208,140,91,195,93,202,10,77,203,126,
			      213,193,49,190,37,37>>,
			    [?DNS_TYPE_NS, ?DNS_TYPE_DS, ?DNS_TYPE_RRSIG]),
    Authority = NS ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = false,
      qc = 1,
      anc = 0,
      auc = 4,
      adc = 3,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'},
		    #dns_rr{name = <<"ns1.c.example">>, _ = '_'},
		    #dns_rr{name = <<"ns2.c.example">>, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

referral_2(Config) ->
    Query = #dns_query{name = <<"mc.c.example">>, type = ?DNS_TYPE_NS},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    NS = ?gen_ms_rr(<<"c.example">>, [?DNS_TYPE_NS, ?DNS_TYPE_NS]),
    NSEC3 = gen_nsec3_ms_rr([{<<"35mthgpgcu1qg68fab165klnsnk3dpvl.example">>,
			      <<89,61,100,25,208,140,91,195,93,202,10,77,203,
				126,213,193,49,190,37,37>>,
			      [?DNS_TYPE_NS, ?DNS_TYPE_DS, ?DNS_TYPE_RRSIG]},
			     {<<"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example">>,
			      <<23,78,178,64,159,226,139,203,72,135,161,131,111,
				149,127,10,132,37,226,123>>,
			      [?DNS_TYPE_MX, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_NS,
			       ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC3PARAM,
			       ?DNS_TYPE_RRSIG]}]),
    Authority = NS ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = false,
      qc = 1,
      anc = 0,
      auc = 6,
      adc = 3,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'},
		    #dns_rr{name = <<"ns1.c.example">>, _ = '_'},
		    #dns_rr{name = <<"ns2.c.example">>, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

wildcard_expansion(Config) ->
    Query = #dns_query{name = <<"a.z.w.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    ANS = ?gen_ms_rr(<<"a.z.w.example">>,
			     [?DNS_TYPE_MX, ?DNS_TYPE_RRSIG]),
    NS = ?gen_ms_rr(<<"example">>,
			    [?DNS_TYPE_NS, ?DNS_TYPE_NS, ?DNS_TYPE_RRSIG]),
    NSEC3 = gen_nsec3_ms_rr(<<"q04jkcevqvmu85r014c7dkba38o0ji5r.example">>,
			    <<217,70,189,29,140,23,191,111,45,254,46,25,107,27,
			      46,223,19,218,37,215>>,
			    [?DNS_TYPE_A, ?DNS_TYPE_RRSIG]),
    Authority = NS ++ NSEC3,
    Hosts = ?gen_ms_rr(<<"ai.example">>,
			       [?DNS_TYPE_A, ?DNS_TYPE_RRSIG, ?DNS_TYPE_AAAA,
				?DNS_TYPE_RRSIG]),
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 2,
      auc = 5,
      adc = 5,
      questions = [Query],
      answers = ANS,
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'}|Hosts],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

wildcard_no_data(Config) ->
    Query = #dns_query{name = <<"a.z.w.example">>, type = ?DNS_TYPE_AAAA},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    SOA = ?gen_ms_rr(<<"example">>, [?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG]),
    NSEC3 = gen_nsec3_ms_rr([{<<"k8udemvp1j2f7eg6jebps17vp3n8i58h.example">>,
			      <<166,34,173,158,203,90,26,193,49,200,82,117,250,
				162,56,185,40,81,250,50>>, []},
			     {<<"q04jkcevqvmu85r014c7dkba38o0ji5r.example">>,
			      <<217,70,189,29,140,23,191,111,45,254,46,25,107,
				27,46,223,19,218,37,215>>,
			      [?DNS_TYPE_A, ?DNS_TYPE_RRSIG]},
			     {<<"r53bq7cc2uvmubfu5ocmm6pers9tk9en.example">>,
			      <<233,136,71,47,84,74,228,182,93,72,57,33,47,236,
				211,196,204,43,86,63>>,
			      [?DNS_TYPE_MX, ?DNS_TYPE_RRSIG]}]),
    Authority = SOA ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      auc = 8,
      adc = 1,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

ds_child_zone_no_data_error(Config) ->
    Query = #dns_query{name = <<"example">>, type = ?DNS_TYPE_DS},
    QMsg = #dns_message{qc = 1, adc = 1, questions = [Query],
			additional = [#dns_optrr{dnssec = true}]},
    SOA = ?gen_ms_rr(<<"example">>, [?DNS_TYPE_SOA, ?DNS_TYPE_RRSIG]),
    NSEC3 = gen_nsec3_ms_rr(<<"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example">>,
			    <<23,78,178,64,159,226,139,203,72,135,161,131,111,
				149,127,10,132,37,226,123>>,
			     [?DNS_TYPE_MX, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_NS,
			      ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC3PARAM,
			      ?DNS_TYPE_RRSIG]),
    Authority = SOA ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      auc = 4,
      adc = 1,
      questions = [Query],
      answers = [],
      authority = Authority,
      additional = [#dns_optrr{dnssec = true, _ = '_'}],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

gen_nsec3_ms_rr(Specs) ->
    lists:flatten([gen_nsec3_ms_rr(Name, NextName, Types)
		   || {Name, NextName, Types} <- Specs ]).

gen_nsec3_ms_rr(Name, NextName, Types) ->
    [#dns_rr{name = Name, type = ?DNS_TYPE_NSEC3,
	     data = #dns_rrdata_nsec3{hash = NextName,
				      types = if is_list(Types) ->
						      lists:sort(Types);
						 true -> Types end,
				      _ = '_'},
	     _ = '_'},
     #dns_rr{name = Name, type = ?DNS_TYPE_RRSIG, _ = '_'}].
