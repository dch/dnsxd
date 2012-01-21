%% -*- mode: erlang -*-
{incl_dirs, ["ebin"]}.
{excl_mods, [dnsxd_couch,dnsxd_couch_app,dnsxd_couch_ds_server,
	     dnsxd_couch_lib,dnsxd_couch_log_server,dnsxd_couch_zone,
	     dnsxd_disklog,dnsxd_shell_admin,dnsxd_shell_admin_dnssec,
	     dnsxd_shell_admin_lib,dnsxd_shell_admin_tsig,
	     dnsxd_shell_admin_zone,dnsxd_shell_disklog,dnsxd_shell_lib,
	     dnsxd_shell_llq,dnsxd_shell_rb]}.
{excl_dirs, ["test"]}.
