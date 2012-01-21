-module(llq_SUITE).
-include("dnsxd_ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([event/1, event_nat/1, timeout_active/1, timeout_setup/1]).

all() -> ?arity1_exports.

rr(Config) ->
    Now = proplists:get_value(now, Config, dns:unix_time()),
    Spec = [{Now, undefined, "b._dns-sd.udp.example", "example"},
	    {Now + 2, Now + 4, "_test._tcp.example", "Test._test._tcp.example"},
	    {Now + 42, undefined, "dummy.example", "avoids.reloading.example"}],
    RR = [#dnsxd_rr{incept = Incept,
		    expire = Expire,
		    name = list_to_binary(Name),
		    data = #dns_rrdata_ptr{dname = list_to_binary(Target)}}
	  || {Incept, Expire, Name, Target} <- Spec ],
    ?update_pl(now, Now, [{rr, RR}|Config]).

init_per_testcase(TestCase, Config) ->
    Config0 = rr(Config),
    Config1 = ?testcase_init(Config0),
    UDPKeepAlive = if TestCase =:= event_nat -> 2; true -> 300 end,
    {ok, LLQOpts} = application:get_env(dnsxd, llq_opts),
    LLQOpts0 = ?update_pl(min_length, 1, LLQOpts),
    LLQOpts1 = ?update_pl(udp_keepalive, UDPKeepAlive, LLQOpts0),
    ok = application:set_env(dnsxd, llq_opts, LLQOpts1),
    ?update_pl(timeout, 10000, Config1).

end_per_testcase(_TestCase, Config) -> ok = ?testcase_end(Config).

event(Config) ->
    %% Setup
    ?p("Initiating setup"),
    Query = #dns_query{name = <<"_test._tcp.example">>, type = ?DNS_TYPE_PTR},
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = 0,
		       leaselife = 600},
    LLQMS0 = LLQ#dns_opt_llq{id = '$1', leaselife = '$2'},
    QMsg0 = #dns_message{qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ]}]},
    RMsg0 = #dns_message{id = QMsg0#dns_message.id,
			 qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQMS0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    [Id, LeaseLife] = ?match_response(Config, QMsg0, RMsg0),
    ?p("Received challenge - ID: ~p LeaseLife ~p", [Id, LeaseLife]),
    %% Respond to challenge
    LLQ0 = LLQ#dns_opt_llq{id = Id, leaselife = LeaseLife},
    QMsg1 = #dns_message{id = QMsg0#dns_message.id, qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ0]}]},
    RMsg1 = #dns_message{id = QMsg1#dns_message.id,
			 qc = 1, questions = [Query],
			 anc = 0,
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQ0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    true = ?match_response(Config, QMsg1, RMsg1),
    ?p("Completed handshake"),
    %% Handle initial event
    LLQ1 = LLQ0#dns_opt_llq{leaselife = '$2', opcode = ?DNS_LLQOPCODE_EVENT},
    RMsg2 = RMsg1#dns_message{id = '$1', anc = '$3', answers = '$4',
			      additional = [#dns_optrr{data = [LLQ1],
						       udp_payload_size = '_'}]
			     },
    [Event1MsgId, LeaseLife0, 0, []] = ?match_message(Config, RMsg2),
    ?p("Received initial event"),
    QMsg2 = #dns_message{id = Event1MsgId, qr = true, qc = 1, adc = 1,
			 questions = [Query],
			 additional = [#dns_optrr{
					  data = [LLQ1#dns_opt_llq{
						    leaselife = LeaseLife0
						   }]
					 }]},
    ok = ?send(Config, QMsg2),
    %% Handle add change event
    [Event2MsgId, _, 1, [#dns_rr{ttl = 1}]] =
	?match_message(Config, RMsg2),
    ?p("Ignored first add change event"),
    [Event2MsgId, LeaseLife1, 1, [#dns_rr{ttl = 1}]] =
	?match_message(Config, RMsg2),
    QMsg3 = #dns_message{id = Event2MsgId, qr = true, qc = 1, adc = 1,
			 questions = [Query],
			 additional = [#dns_optrr{
					  data = [LLQ1#dns_opt_llq{
						    leaselife = LeaseLife1
						   }]
					 }]},
    ok = ?send(Config, QMsg3),
    ?p("Acknowledged second add change event"),
    %% Handle remove change event
    [Event3MsgId, LeaseLife2, 1, [#dns_rr{ttl = -1}]] =
	?match_message(Config, RMsg2),
    ?p("Received remove change event"),
    QMsg4 = #dns_message{id = Event3MsgId, qr = true, qc = 1, adc = 1,
			 questions = [Query],
			 additional = [#dns_optrr{
					  data = [LLQ1#dns_opt_llq{
						    leaselife = LeaseLife2
						   }]
					 }]},
    ok = ?send(Config, QMsg4),
    ?p("Acknowledged remove change event"),
    %% Cancel LLQ
    LLQ2 = LLQ1#dns_opt_llq{opcode = ?DNS_LLQOPCODE_REFRESH, leaselife = 0},
    QMsg6 = #dns_message{qr = false, qc = 1, adc = 1, questions = [Query],
			 additional = [#dns_optrr{data = [LLQ2]}]},
    ok = ?send(Config, QMsg6),
    RMsg3 = #dns_message{id = QMsg6#dns_message.id, qr = true, _ = '_'},
    true = ?match_message(Config, RMsg3),
    ?p("Cancelled LLQ"),
    fail_if_llq(Id).

event_nat(Config) ->
    %% Setup
    ?p("Setup"),
    Query = #dns_query{name = <<"_test2._tcp.example">>, type = ?DNS_TYPE_PTR},
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = 0,
		       leaselife = 600},
    LLQMS0 = LLQ#dns_opt_llq{id = '$1', leaselife = '$2'},
    QMsg0 = #dns_message{qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ]}]},
    RMsg0 = #dns_message{id = QMsg0#dns_message.id,
			 qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQMS0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    [Id, LeaseLife] = ?match_response(Config, QMsg0, RMsg0),
    %% Respond to challenge
    ?p("Respond to challenge"),
    LLQ0 = LLQ#dns_opt_llq{id = Id, leaselife = LeaseLife},
    QMsg1 = #dns_message{id = QMsg0#dns_message.id, qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ0]}]},
    RMsg1 = #dns_message{id = QMsg1#dns_message.id,
			 qc = 1, questions = [Query],
			 anc = 0,
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQ0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    true = ?match_response(Config, QMsg1, RMsg1),
    %% Handle initial event
    ?p("Handle initial event"),
    LLQ1 = LLQ0#dns_opt_llq{leaselife = '$2', opcode = ?DNS_LLQOPCODE_EVENT},
    RMsg2 = RMsg1#dns_message{id = '$1', anc = '$3', answers = '$4',
			      additional = [#dns_optrr{data = [LLQ1],
						       udp_payload_size = '_'}]
			     },
    [Event1MsgId, LeaseLife0, 0, []] = ?match_message(Config, RMsg2),
    QMsg2 = #dns_message{id = Event1MsgId, qr = true, qc = 1, adc = 1,
			 questions = [Query],
			 additional = [#dns_optrr{
					  data = [LLQ1#dns_opt_llq{
						    leaselife = LeaseLife0
						   }]
					 }]},
    ok = ?send(Config, QMsg2),
    %% Handle NAT keepalive event
    ?p("Handle NAT keepalive event"),
    [Event2MsgId, LeaseLife1, 0, []] = ?match_message(Config, RMsg2),
    QMsg3 = #dns_message{id = Event2MsgId, qr = true, qc = 1, adc = 1,
			 questions = [Query],
			 additional = [#dns_optrr{
					  data = [LLQ1#dns_opt_llq{
						    leaselife = LeaseLife1
						   }]
					 }]},
    ok = ?send(Config, QMsg3),
    %% Cancel LLQ
    LLQ2 = LLQ1#dns_opt_llq{opcode = ?DNS_LLQOPCODE_REFRESH, leaselife = 0},
    QMsg6 = #dns_message{qr = false, qc = 1, adc = 1, questions = [Query],
			 additional = [#dns_optrr{data = [LLQ2]}]},
    ok = ?send(Config, QMsg6),
    ?p("Cancelled LLQ"),
    RMsg3 = #dns_message{id = QMsg6#dns_message.id, qr = true, _ = '_'},
    true = ?match_message(Config, RMsg3),
    fail_if_llq(Id).

timeout_active(Config) ->
    %% Setup
    ?p("Setup"),
    Query = #dns_query{name = <<"_test3._tcp.example">>, type = ?DNS_TYPE_PTR},
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = 0,
		       leaselife = 600},
    LLQMS0 = LLQ#dns_opt_llq{id = '$1', leaselife = '$2'},
    QMsg0 = #dns_message{qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ]}]},
    RMsg0 = #dns_message{id = QMsg0#dns_message.id,
			 qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQMS0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    [Id, LeaseLife] = ?match_response(Config, QMsg0, RMsg0),
    %% Respond to challenge
    ?p("Respond to challenge"),
    LLQ0 = LLQ#dns_opt_llq{id = Id, leaselife = LeaseLife},
    QMsg1 = #dns_message{id = QMsg0#dns_message.id, qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ0]}]},
    RMsg1 = #dns_message{id = QMsg1#dns_message.id,
			 qc = 1, questions = [Query],
			 anc = 0,
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQ0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    true = ?match_response(Config, QMsg1, RMsg1),
    %% Ignore events
    LLQ1 = LLQ0#dns_opt_llq{leaselife = '_', opcode = ?DNS_LLQOPCODE_EVENT},
    RMsg2 = RMsg1#dns_message{id = '$1', anc = 0, answers = [],
			      additional = [#dns_optrr{data = [LLQ1],
						       udp_payload_size = '_'}]
			     },
    [EventMsgId] = ?match_message(Config, RMsg2),
    ?p("Ignored event 1"),
    [EventMsgId] = ?match_message(Config, RMsg2),
    ?p("Ignored event 2"),
    [EventMsgId] = ?match_message(Config, RMsg2),
    ?p("Ignored event 3"),
    ok = timer:sleep(10000),
    fail_if_llq(Id).

timeout_setup(Config) ->
    %% Setup
    ?p("Setup"),
    Query = #dns_query{name = <<"_test3._tcp.example">>, type = ?DNS_TYPE_PTR},
    LLQ = #dns_opt_llq{opcode = ?DNS_LLQOPCODE_SETUP,
		       errorcode = ?DNS_LLQERRCODE_NOERROR,
		       id = 0,
		       leaselife = 1},
    LLQMS0 = LLQ#dns_opt_llq{id = '$1', leaselife = '_'},
    QMsg0 = #dns_message{qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{data = [LLQ]}]},
    RMsg0 = #dns_message{id = QMsg0#dns_message.id,
			 qc = 1, questions = [Query],
			 adc = 1, additional = [#dns_optrr{
						   data = [LLQMS0],
						   udp_payload_size = '_'}],
			 _ = '_'},
    [Id] = ?match_response(Config, QMsg0, RMsg0),
    ?p("Challenge received - ignoring"),
    ok = timer:sleep(2000),
    fail_if_llq(Id).

fail_if_llq(Id) ->
    ActiveLLQ = dnsxd_llq_manager:list_llq(),
    case lists:keymember(Id, 1, ActiveLLQ) of
	true -> {fail, {llq_active, dns:unix_time()}};
	false -> ok
    end.
