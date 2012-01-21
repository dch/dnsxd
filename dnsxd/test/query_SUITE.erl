-module(query_SUITE).
-include("dnsxd_ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([any/1, any_ds/1, cname/1, cname_any/1, cname_any_wild/1,
	 cname_any_bad/1, cname_wild_dnssec/1, no_zone/1]).

all() -> ?arity1_exports.

rr(Config) ->
    RR = [#dnsxd_rr{data = #dns_rrdata_ns{dname = <<"ns.example.com">>}},
	  #dnsxd_rr{data = #dns_rrdata_ns{dname = <<"ns.example.net">>}},
	  #dnsxd_rr{data = #dns_rrdata_txt{txt = [<<?MODULE_STRING>>]}},
	  #dnsxd_rr{name = <<"*.cname.example">>,
		     data = #dns_rrdata_cname{dname = <<"example">>}},
	  #dnsxd_rr{name = <<"good.cname.example">>,
		    data = #dns_rrdata_cname{dname = <<"example">>}},
	  #dnsxd_rr{name = <<"bad.cname.example">>,
		    data = #dns_rrdata_cname{dname = <<"bad.cname.example">>}}],
    [{rr, RR}|Config].

init_per_testcase(_TestCase, Config) ->
    ?testcase_init(rr([{dnssec, true}|Config])).

end_per_testcase(_TestCase, Config) -> ok = ?testcase_end(Config).

any(Config) ->
    Query = #dns_query{name = <<"example">>, type = ?DNS_TYPE_ANY},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    An = ?gen_ms_rr(<<"example">>,
			    [?DNS_TYPE_NS, ?DNS_TYPE_NS, ?DNS_TYPE_SOA,
			     ?DNS_TYPE_TXT, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_DNSKEY,
			     ?DNS_TYPE_NSEC3PARAM]),
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 7,
      questions = [Query],
      answers = An,
      _ = '_'
     },
    ?match_response(Config, QMsg, RMsg).

any_ds(Config) ->
    Query = #dns_query{name = <<"ka._dnsxd-ds.example">>, type = ?DNS_TYPE_ANY},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 1,
      auc = 2,
      questions = [Query],
      answers = [?gen_ms_rr(<<"ka._dnsxd-ds.example">>, ?DNS_TYPE_DS)],
      authority = ?gen_ms_rr(<<"example">>,
				     [?DNS_TYPE_NS, ?DNS_TYPE_NS]),
      _ = '_'
     },
    ?match_response(Config, QMsg, RMsg).

cname(Config) ->
    Query = #dns_query{name = <<"good.cname.example">>, type = ?DNS_TYPE_CNAME},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 1,
      questions = [Query],
      answers = [?gen_ms_rr(<<"good.cname.example">>, ?DNS_TYPE_CNAME)],
      _ = '_'
     },
    ?match_response(Config, QMsg, RMsg).

cname_any(Config) ->
    Query = #dns_query{name = <<"good.cname.example">>, type = ?DNS_TYPE_ANY},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    An = [?gen_ms_rr(<<"good.cname.example">>, ?DNS_TYPE_CNAME)|
	  ?gen_ms_rr(<<"example">>,
			     [?DNS_TYPE_NS, ?DNS_TYPE_NS, ?DNS_TYPE_SOA,
			      ?DNS_TYPE_TXT, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_DNSKEY,
			      ?DNS_TYPE_NSEC3PARAM])],
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 8,
      questions = [Query],
      answers = An,
      _ = '_'
     },
    ?match_response(Config, QMsg, RMsg).

cname_any_wild(Config) ->
    Query = #dns_query{name = <<"wild.cname.example">>, type = ?DNS_TYPE_ANY},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    An = [?gen_ms_rr(<<"wild.cname.example">>, ?DNS_TYPE_CNAME)|
	  ?gen_ms_rr(<<"example">>,
			     [?DNS_TYPE_NS, ?DNS_TYPE_NS, ?DNS_TYPE_SOA,
			      ?DNS_TYPE_TXT, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_DNSKEY,
			      ?DNS_TYPE_NSEC3PARAM])],
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 8,
      questions = [Query],
      answers = An,
      _ = '_'
     },
    ?match_response(Config, QMsg, RMsg).

cname_any_bad(Config) ->
    Query = #dns_query{name = <<"bad.cname.example">>, type = ?DNS_TYPE_ANY},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{id = QMsg#dns_message.id,
			rc = ?DNS_RCODE_SERVFAIL,
			_ = '_'},
    ?match_response(Config, QMsg, RMsg).

cname_wild_dnssec(Config) ->
    Query = #dns_query{name = <<"wild.cname.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, questions = [Query],
			adc = 1, additional = [#dns_optrr{dnssec = true}]},
    An = ?gen_ms_rr(<<"wild.cname.example">>,
			    [?DNS_TYPE_CNAME, ?DNS_TYPE_RRSIG]),
    NS = ?gen_ms_rr(<<"example">>,
			    [?DNS_TYPE_NS, ?DNS_TYPE_NS, ?DNS_TYPE_RRSIG]),
    NSEC3 = ?gen_ms_rr(<<"277b9s4s52mnhpiobdg0i5625h4us42h.example">>,
			       [?DNS_TYPE_NSEC3, ?DNS_TYPE_RRSIG]),
    Au = NS ++ NSEC3,
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 2,
      auc = 5,
      questions = [Query],
      answers = An,
      authority = Au,
      _ = '_'
     },
    ?match_response(Config, QMsg, RMsg).

no_zone(Config) ->
    Query = #dns_query{name = <<?MODULE_STRING>>, type = ?DNS_TYPE_SOA},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{id = QMsg#dns_message.id,
			rc = ?DNS_RCODE_REFUSED,
			_ = '_'},
    ?match_response(Config, QMsg, RMsg).
