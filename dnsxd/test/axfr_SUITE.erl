-module(axfr_SUITE).
-include("dnsxd_ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([accept/1, refuse1/1, refuse2/1]).

all() -> ?arity1_exports.

rr(Config) ->
    RR = [ begin
	       TXT = lists:duplicate(42, list_to_binary(integer_to_list(N))),
	       #dnsxd_rr{data = #dns_rrdata_txt{txt = TXT}}
	   end || N <- lists:seq(1, 418) ],
    [{rr, RR}|Config].

init_per_testcase(TestCase, Config) ->
    Config0 = rr([{transport, tcp},
		  {axfr_disabled, TestCase =:= refuse1},
		  {axfr_hosts, if TestCase =:= refuse2 -> [<<"127.0.0.2">>];
				  true -> [] end}|Config]),
    ?testcase_init(Config0).

end_per_testcase(_TestCase, Config) -> ok = ?testcase_end(Config).

accept(Config) ->
    Query = #dns_query{name = <<"example">>,
		       class = ?DNS_CLASS_IN,
		       type = ?DNS_TYPE_AXFR},
    QMsg = #dns_message{qc = 1, questions = [Query]},
    RMsg = #dns_message{id = QMsg#dns_message.id,
			rc = ?DNS_RCODE_NOERROR,
			qc = '$1',
			anc = '$3',
			questions = '$2',
			answers = '$4',
			_ = '_'},
    [1, [Query], 389, [#dns_rr{type = ?DNS_TYPE_SOA}|_]] =
	?match_response(Config, QMsg, RMsg),
    [0, [], 31, Tail] = ?match_response(Config, QMsg, RMsg),
    #dns_rr{type = ?DNS_TYPE_SOA} = hd(lists:reverse(Tail)),
    ok.

refuse1(Config) ->
    QMsg = #dns_message{qc = 1,
			questions = [#dns_query{name = <<"example">>,
						class = ?DNS_CLASS_IN,
						type = ?DNS_TYPE_AXFR}]},
    RMsg = #dns_message{id = QMsg#dns_message.id, qr = true,
			rc = ?DNS_RCODE_REFUSED, _ = '_'},
    ?match_response(Config, QMsg, RMsg).

refuse2(Config) -> refuse1(Config).
