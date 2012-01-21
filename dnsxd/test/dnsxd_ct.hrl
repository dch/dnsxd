-ifndef('__dnsxd_ct.hrl__').
-define('__dnsxd_ct.hrl__', ok).

-include("dnsxd.hrl").

-define(p, ct:pal).

-define(update_pl(Key, Value, PL), [{Key, Value}|proplists:delete(Key, PL)]).

-define(arity1_exports, [ M || {M,1} <- ?MODULE:module_info(exports),
			       M =/= module_info ]).

-define(testcase_init(C), dnsxd_ct:testcase_init(C)).
-define(testcase_end(C), dnsxd_ct:testcase_end(C)).

-define(gen_ms_rr(N, T), dnsxd_ct:gen_ms_rr(N,T)).
-define(send(C, M), dnsxd_ct:send(C, M)).
-define(match_response(C, Q, R), dnsxd_ct:match_response(C, Q, R)).
-define(match_message(C, R), dnsxd_ct:match_message(C, R)).

-endif.
