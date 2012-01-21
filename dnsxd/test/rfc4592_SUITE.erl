-module(rfc4592_SUITE).
-include("dnsxd_ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([synth1/1, synth2/1, synth3/1, nx1/1, nx2/1, nx3/1, nx4/1, nx5/1]).

all() -> ?arity1_exports.

rr(Config) ->
    RR = [#dnsxd_rr{data = #dns_rrdata_ns{dname = <<"ns.example.com">>}},
	  #dnsxd_rr{data = #dns_rrdata_ns{dname = <<"ns.example.net">>}},
	  #dnsxd_rr{name = <<"*.example">>,
		    data = #dns_rrdata_txt{txt = [<<"this is a wildcard">>]}},
	   #dnsxd_rr{name = <<"*.example">>,
		     data = #dns_rrdata_mx{preference = 10,
					   exchange = <<"host1.example">>}},
	  #dnsxd_rr{name = <<"sub.*.example">>,
		    data = #dns_rrdata_txt{
		      txt = [<<"this is not a wildcard">>]}},
	  #dnsxd_rr{name = <<"host1.example">>,
		    data = #dns_rrdata_a{ip = <<"192.0.2.1">>}},
	  #dnsxd_rr{name = <<"_ssh._tcp.host1.example">>,
		    data = #dns_rrdata_srv{priority = 0,
					   weight = 0,
					   port = 1,
					   target = <<"host1.example">>}},
	  #dnsxd_rr{name = <<"_ssh._tcp.host2.example">>,
		    data = #dns_rrdata_srv{priority = 0,
					   weight = 0,
					   port = 1,
					   target = <<"host1.example">>}},
	  #dnsxd_rr{name = <<"subdel.example">>,
		    data = #dns_rrdata_ns{dname = <<"ns.example.com">>}},
	  #dnsxd_rr{name = <<"subdel.example">>,
		    data = #dns_rrdata_ns{dname = <<"ns.example.net">>}}],
    [{rr, RR}|Config].

init_per_testcase(_TestCase, Config) -> ?testcase_init(rr(Config)).

end_per_testcase(_TestCase, Config) -> ok = ?testcase_end(Config).

synth1(Config) ->
    Query = #dns_query{name = <<"host3.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 1,
      questions = [Query],
      answers = [?gen_ms_rr(<<"host3.example">>, ?DNS_TYPE_MX)],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

synth2(Config) ->
    Query = #dns_query{name = <<"host3.example">>, type = ?DNS_TYPE_A},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      rc = ?DNS_RCODE_NOERROR,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      questions = [Query],
      answers = [],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

synth3(Config) ->
    Query = #dns_query{name = <<"foo.bar.example">>, type = ?DNS_TYPE_TXT},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      qr = true,
      aa = true,
      qc = 1,
      anc = 1,
      questions = [Query],
      answers = [?gen_ms_rr(<<"foo.bar.example">>, ?DNS_TYPE_TXT)],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

nx1(Config) ->
    Query = #dns_query{name = <<"host1.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      rc = ?DNS_RCODE_NOERROR,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      questions = [Query],
      answers = [],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

nx2(Config) ->
    Query = #dns_query{name = <<"sub.*.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      rc = ?DNS_RCODE_NOERROR,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      questions = [Query],
      answers = [],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

nx3(Config) ->
    Query = #dns_query{name = <<"_telnet._tcp.host1.example">>,
		       type = ?DNS_TYPE_SRV},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      rc = ?DNS_RCODE_NXDOMAIN,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      questions = [Query],
      answers = [],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

nx4(Config) ->
    Query = #dns_query{name = <<"host.subdel.example">>, type = ?DNS_TYPE_A},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      rc = ?DNS_RCODE_NOERROR,
      qr = true,
      aa = false,
      qc = 1,
      anc = 0,
      questions = [Query],
      answers = [],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).

nx5(Config) ->
    Query = #dns_query{name = <<"ghost.*.example">>, type = ?DNS_TYPE_MX},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{
      id = QMsg#dns_message.id,
      rc = ?DNS_RCODE_NXDOMAIN,
      qr = true,
      aa = true,
      qc = 1,
      anc = 0,
      questions = [Query],
      answers = [],
      _ = '_'},
    ?match_response(Config, QMsg, RMsg).
