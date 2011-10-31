""" config module for nagiosnmapperper
"""

# map service names as reported by nmap to Nagios commands. A value of 
# None indicates that this service should be ignored by Nagios.  The 
# default for a service not in the map is ( "servicename", "check_servicename" )
nagios_command_map = {

	# PORT      ( SERVICE DESC, CHECK_COMMAND )
	   53   : ( 'DNS', r'check_dns' ),
	  135   : ( 'RPC Locator', r'check_tcp!__PORT__!' ),
	  311   : ( 'OS X ServerAdmin', r'check_https!__PORT__!' ),
	  443   : ( 'HTTPS', r'check_https!__PORT__' ),
	  445   : ( 'CIFS', r'check_cifs' ),
	  548   : ( 'AFP', r'check_osx_afp!afp!$USER3$!$USER4$!' ),
	  593   : ( 'RPC-over-HTTP', r'check_http!__PORT__' ),
	  612   : ( 'NIS', r'check_nis!__NISDOMAIN__!' ),
	  636   : ( 'LDAPs ', r'check_tcp!__PORT__!'),
	 1347   : ( 'Ghostcast Server', r'check_tcp!__PORT__!' ),
	 2002   : ( 'LogMeIn', r'check_tcp!__PORT__!' ),
	 2049   : ( 'NFS', r'check_nfsmount' ),
	 2301   : ( 'HP Mgmt Console', r'check_http!__PORT__' ),
	 2381   : ( 'HP Monitor', r'check_tcp!__PORT__'),
	 3306   : ( 'MySQL', r'check_mysql' ),
	 3268   : ( 'LDAP Global Cat', r'check_ldap!__PORT__!__LDAPSEARCHBASE__!__LDAPBINDDN__!__LDAPBINDPWD__!' ),
	 3269   : ( 'LDAP Global Cat SSL', r'check_tcp!__PORT__!'),
	 3389   : ( 'RDP', r'check_rdp!__PORT__!' ),
	 5900   : ( 'VNC', r'check_vnc!__PORT__!' ),
	 5901   : ( 'VNC', r'check_vnc!__PORT__!' ),
	 5902   : ( 'VNC', r'check_vnc!__PORT__!' ),
	 5999   : ( 'IRC', r'check_irc!__PORT__!' ),
	 6667   : ( 'IRC', r'check_irc!__PORT__!' ),
	 8080   : ( 'HTTP 8080', r'check_http!__PORT__!' ),
	 9389   : ( 'AD Web Services', r'check_tcp!__PORT__!' ),
	10000   : ( 'Veritas BackupExec', r'check_tcp!__PORT__!' ),
	28518   : ( 'FlexLM', r'check_tcp!__PORT__!' ),
	47001   : ( 'WinRM', r'check_http!__PORT__!' ),

	# IGNORE THESE PORTS
	  111   : None, # rpcbind
	   88   : None, # kerberos-sec
	  137   : None, # netbios-ns
	  139   : None, # netbios-ssn
	  464   : None, # kpasswd5
	  625   : None, # apple-xsrvr-admin
	  749   : None, # kerberos-adm
	 1020   : None, # nfs.lockd
	 1021   : None, # nfs.statd
	 1022   : None, # nfs.server
	 1023   : None, # nfs.server
	 4502   : None, # ?? os x server
	 8009   : None, # ajp13
	10080   : None, # xinetd

}

# ignore all ephemeral ports
for n in range(49152,65535):
	nagios_command_map[n] = None

# macros that should be expanded in check command definitions 
# inherited from nagios_command_map
macros = {
	'__NISDOMAIN__'       : '',
	'__LDAPSEARCHBASE__'  : '',
	'__LDAPBINDDN__'      : '',
	'__LDAPBINDPWD__'     : '',
}

# The list of checks that should always be added to a new host.  the list of 
# tuples in common_checks['all'] get added to every host; other keys refer to 
# specific operating systems.
#
# TODO: Support better OS detection here? (OS X Server vs OS X, eg)
common_checks = {

	# Not much applies to all operating system and 'embedded' devices, 
	# but maybe a ping check or something, if applicable.
	'all' : [
	],

	# TODO: Can we check system updates by grepping syslog or similar?
	'Mac OS X' : [
		( 'Time Machine',     r'check_nrpe!5666!10!check_backupd!7200!43200!' ),
		( 'Total Procs',      r'check_nrpe!5666!10!check_total_procs!'  ),
		( 'Zombie Procs',     r'check_nrpe!5666!10!check_zombie_procs!' ),
		( 'Disk /',           r'check_nrpe!5666!10!check_disk'          ),
		( 'Users',            r'check_nrpe!5666!10!check_users'         ),
		( 'Load',             r'check_nrpe!5666!10!check_load'          ) 
	],

	# TODO: Check windows updates? domain users?
	'Windows' : [
		( 'Clock',            r'check_nrpe!5666!10!check_ntp_time!'     ),
		( 'Disk /',           r'check_nrpe!5666!10!check_disk'          ),
		( 'Users',            r'check_nrpe!5666!10!check_users'         ),
		( 'Load',             r'check_nrpe!5666!10!check_load'          ) 
	],

	# TODO: Split up into debian/rhel/centos/etc and monitor package 
	# management freshness, updates etc.
	'Linux' : [
		( 'Clock',            r'check_nrpe!5666!10!check_ntp_time!'     ),
		( 'Total Procs',      r'check_nrpe!5666!10!check_total_procs!'  ),
		( 'Zombie Procs',     r'check_nrpe!5666!10!check_zombie_procs!' ),
		( 'Disk /',           r'check_nrpe!5666!10!check_disk'          ),
		( 'Users',            r'check_nrpe!5666!10!check_users'         ),
		( 'Load',             r'check_nrpe!5666!10!check_load'          ) 
	],

	# TODO: add check of ports freshness, available updates 
	'FreeBSD' : [ 
		( 'Clock',            r'check_nrpe!5666!10!check_ntp_time!'     ),
		( 'Total Procs',      r'check_nrpe!5666!10!check_total_procs!'  ),
		( 'Zombie Procs',     r'check_nrpe!5666!10!check_zombie_procs!' ),
		( 'Disk /',           r'check_nrpe!5666!10!check_disk'          ),
		( 'Users',            r'check_nrpe!5666!10!check_users'         ),
		( 'Load',             r'check_nrpe!5666!10!check_load'          ) ,
	],

	# phones, switches, wifi lightbulbs, etc.
	'embedded' : [ 
	],
	
}

# list of FQDNs that we should not automatically add to nagios
ignored_hosts = [
	'foo.internal',
	'bar.internal',
]

# icon image relatives paths, by operating system
icon_image = {
	'Mac OS X' :  { 'icon' : 'base/mac40.gif',       'statusmap'  : 'base/mac40.gd2' },
	'Windows'  :  { 'icon' : 'base/win40.gif',       'statusmap'  : 'base/win40.gd2' },
	'Linux'    :  { 'icon' : 'base/linux40.gif',     'statusmap'  : 'base/linux40.gd2' },
	'FreeBSD'  :  { 'icon' : 'base/freebsd40.gif',   'statusmap'  : 'base/freebsd40.gd2' },
}

# generic host template for new nagios host entries
# TODO: Add support for parents
host_template = """
# automatically generated by nagiosnmapper.py on %s
define host {
    host_name                    %s
    alias                        %s
    address                      %s
    check_command                check-host-alive
    max_check_attempts           3
    notification_interval        120
    active_checks_enabled        1
    passive_checks_enabled       1
    flap_detection_enabled       1
    process_perf_data            1
    retain_status_information    1
    retain_nonstatus_information 1
    check_period                 24x7
    notification_period          24x7
    notifications_enabled        1
    contact_groups               admins
    notification_options         d,u,r
    use                          Default_timeperiod_interval_5
}
define hostextinfo {
    host_name                    %s
    icon_image                   %s
    icon_image_alt               %s
    statusmap_image              %s
}
"""

# generic service template for new nagios service entries
# TODO: Add support for parents
service_template = """
define service {
        host_name                   %s
        service_description         %s
        check_command               %s
        check_period                24x7
        notification_period         24x7
        contact_groups              admins
        notification_interval       1440
        notification_options        w,u,c,r
        max_check_attempts          3
        check_interval              5
        retry_interval              1
        active_checks_enabled       1
        passive_checks_enabled      1
        notifications_enabled       1
        check_freshness             0
        freshness_threshold         86400
}
"""

# hostgroup template
hostgroup_template = """
# automatically generated by nagiosnmapper.py on %s
define hostgroup {
    hostgroup_name  %s
    alias           %s
    members         %s
    notes           %s
    notes_url       %s
    action_url      %s
}
"""
