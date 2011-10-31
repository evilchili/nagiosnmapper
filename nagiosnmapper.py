#!/usr/bin/python -u
"""
Scan a host or network block with nmap and generate nagios configurations.
"""
__copyright__  = "Copyright 2011, Greg Boyington"
__author__     = 'Greg Boyington <evilchili@gmail.com>'
__version__    = '0.1'
__license__    = "Simplified BSD"
__maintainer__ = 'Greg Boyington'
__email__      = 'evilchili@gmail.com'
__status__     = 'Development'

import sys
import os
import nmap
import re
import socket
import types
from time import strftime, time
from pynag import Parsers
from datetime import timedelta

# import the nagiosnmapperper configuration module
from config import *

config = {}


def scan_start( target ):
	""" callback function called when a new scan is initiated.
	"""
	if config['verbose']:
		sys.stdout.write( target + "..." )


def scan_end( completed ):
	""" callback function called when an entire nmap scan is complete.
	"""
	pass


def one_scan_complete( target, result ):
	""" callback function called when the scan of a single host finishes.
	"""

	# we cannot process negative nmap results. If you get this a lot,
	# consider changing your nmap arguments (with nagiosnmapper.py -o )
	if result is None or target not in result['scan']:
		print '%s host is down or blocking scans; skipping.' % { True: '', False: target + '...' }[ config['verbose'] ]
		return

	info = result[ 'scan' ][ target ]

	# should we skip adding this host to Nagios?
	skip=False
	skip_reason = ''

	# Ignore any host not registered in DNS
	# TODO: Make this a command-line switch
	if 'hostname' not in info or not info['hostname']:
		sys.stderr.write("WARNING: Host %s is up but is not in DNS.\n" % target )
		print '%s host is up but not in DNS; skipping.' % { True: '', False: target + '...' }[ config['verbose'] ]
		info['hostname'] = '???'
		skip_reason = 'no DNS'
		skip=True

	elif info['hostname'] in ignored_hosts:
		if config['verbose']:
			print 'host is up but listed in ignored_hosts; will not add to Nagios.'
		skip_reason = 'ignored'
		skip=True

	# if the hostname contains invalid characters (ACTIVE DIRECTORY), we cannot continue.
	elif re.search( '[^\w\.\-\_\d]', info['hostname'] ) is not None:
		sys.stderr.write( "WARNING: %s hostname '%s' contains invalid characters; skipping.\n" % ( target, info['hostname'] ) )
		skip_reason = 'bad hostname'
		skip=True

	# locate the nagios host entry, if it exists. Try the FQDN first, then 
	# try the hostname portion.
	nagios_object = nc.get_host( info['hostname'] )
	if not nagios_object:
		nagios_object = nc.get_host( info['hostname'].split('.')[0] )

	# list the services nmap found on this host
	services = list_services( info, nagios_object )

	if len(services) is 0:
		skip_reason = 'No services detected.'
		skip=True

	# add the host to nagios, if necessary
	is_new = False
	if skip:
		is_new = None
	elif not nagios_object:
		nagios_object = add_host_to_nagios( target, info, services )
		if not nagios_object:
			print "%s ERROR: Could not create Nagios host entry; skipping." % target
			return
		is_new = True

	# print a summary of the scan
	print_scan_summary( target, info, services, is_new, skip_reason )


def print_scan_summary( target, info, services, is_new, skip_reason='' ):
	""" Print some formatted summary info to STDOUT.
	"""

	# short status output
	if config['verbose'] or is_new:
		if not config['verbose']:
			sys.stdout.write( target+'...' )

		if 'os' in info: 
			os = info['os']['family']
		else:
			os = '???'

		print 'hostname: %s OS: %s services: %d nagios: %s' % ( 
			info[ 'hostname' ], 
			os,
			len(services), 
			{ True:'NEW', False:'exists', None: 'SKIPPED (%s)' % skip_reason  }[ is_new ] 
		)

	# print a verbose list of all open ports (minus ones we're ignoring)
	if config['verbose']:
		print '%4s %5s %-20s %-20s %s' % ( 'STAT', 'PORT', 'SERVICE', 'NAGIOS DESC','CHECK COMMAND' )
		for s in services:
			print " %1s%1s %6d %-20s %-20s %s" % ( 
				{ True:'',  False:'!' }[ s['valid']  ], 
				{ True:'*', False:''  }[ s['exists'] ], 
				s[ 'nmap_port' ], 
				s[ 'nmap_name' ], 
				s[ 'service_desc' ], 
				s[ 'check_command' ] )
		print ""


def output_dir():
	""" return the full path to the directory in which to create new nagios config files.
	"""
	return os.path.join( os.path.dirname( os.path.abspath( config['nagios_config'] ) ), 'domains/autodiscovery' )


def create_output_dir():
	""" create the output directory for new nagios config files, if necessary.
	"""
	p = output_dir()
	if not os.path.exists( p ):
		os.mkdir( p )
	return p


def add_host_to_nagios( address, host, services, nagios_host_object=None ):
	""" add the specified host definition to the Nagios configuration.
	"""

	# set some OS-specific extended host info, if we can
	os_name=''
	icon=''
	statusmap_icon=''
	if 'os' in host:
		os_name = host['os']['family']
		if os_name in icon_image:
			icon           = icon_image[ os_name ]['icon']
			statusmap_icon = icon_image[ os_name ]['statusmap']

	# get and/or create the output directory
	path = create_output_dir()

	# write a host configuration file
	fh = open( os.path.join( path, "%s.cfg" % host['hostname'] ), "w" )
	fh.write( host_template % ( 
		strftime("%a, %d %b %Y %H:%M:%S +0000"), 
		host['hostname'], 
		host['hostname'].split('.')[0], 
		address,
		host['hostname'],
		icon, 	
		os_name,
		statusmap_icon,
	) )

	# add the discovered services to this configuration
	for service in services:

		# we do not try to create check_commands.
		# TODO: Should we try to create check_commands?
		cmd = nc.get_command( service['command_name'] )
		if not cmd:
			sys.stderr.write( "WARNING: %s: Cannot create service for non-existent command %s; skipping.\n" % ( host['hostname'], service['command_name'] ) )
			sys.stderr.flush()
			continue;

		# add the service definition to the config file
		fh.write( service_template % ( host['hostname'], service['service_desc'], service['check_command'] ) )

	fh.close()

	# add the host to the "autodiscovery" hostgroup
	# TODO: Make this a command-line option
	if host['hostname'] != '???':
		add_host_to_hostgroup( host['hostname'], hostgroup_name='autodiscovery', alias='Autodiscovered Hosts' )

	# reparse the nagios config
	nc.extended_parse()

	# return the config object
	return nc.get_host( host['hostname'] )


def add_host_to_hostgroup( hostname, hostgroup_name=None, alias='' ):
	""" Add a host to the specified hostgroup.
	"""

	path = create_output_dir()

	# retrieve the hostroup from nagios
	hostgroup = nc.get_hostgroup( hostgroup_name )

	# if the hostgroup doesn't exist, create it.
	if not hostgroup:
		fh = open( os.path.join( path, '%s-hostgroup.cfg' % hostgroup_name ), 'w' )
		fh.write( hostgroup_template % (
			strftime("%a, %d %b %Y %H:%M:%S +0000"), 
			hostgroup_name,
			alias,
			hostname,
			'nagiosnmapper.py v%s' % __version__,
			'', 
			''
		) )
		fh.close()

		nc.extended_parse()

		hostgroup = nc.get_hostgroup( hostgroup_name )

	# add the hostname to the members of this hostgroup
	# if it isn't there already.
	members = []
	if hostgroup['members'] is not None:
		members = hostgroup['members'].split(',')
	if hostname not in members:
		members.append(hostname)
		fh = open( hostgroup['meta']['filename'], 'w' )
		fh.write( hostgroup_template % (
			strftime("%a, %d %b %Y %H:%M:%S +0000"), 
			hostgroup['hostgroup_name'],
			hostgroup['alias'],
			','.join( members ),
			hostgroup['notes'],
			hostgroup['notes_url'],
			hostgroup['action_url'],
		) )
		fh.close()

	


def get_nagios_check_for_nmap_service( service, nagios_host_object=None, cmd=None ):
	""" generate a dictionary defining a nagios service check 
		for the corresponding nmap service.
	"""

	# set some defaults
	nagios_desc			= service[ 'name' ]
	nagios_cmd			= cmd or 'check_' + service[ 'name' ]
	nagios_cmd_name		= nagios_cmd

	# handle command definitions in the nagios_command_map
	if service[ 'port' ] in nagios_command_map:

		# ignore services we don't care about
		if nagios_command_map[ service['port'] ] == None:
			return {}

		# override nagios_cmd with the value in nagios_command_map, if any
		else:
			( nagios_desc, nagios_cmd ) = nagios_command_map[ service['port'] ]

	# resolve placeholders in the check command 
	nagios_cmd = expand_macros( nagios_cmd, service )

	# pull out the command name from the entire check_command
	# ie, check_foo!bar!baz! becomes check_foo
	nagios_cmd_name = nagios_cmd.split('!')[0]

	service_dict = {
		'nmap_name'		: service['name'],
		'nmap_port'		: service['port'],
		'service_desc'	: nagios_desc,
		'command_name'  : nagios_cmd_name,
		'check_command' : nagios_cmd
	}
	return service_dict


def expand_macros( cmd, service ):
	""" Replace instances of __MACRO__ strings in a command definition
		with the appropriate service info or macro defintion.
	"""
	# service-specific macros get resolved first
	cmd = re.sub( r'__PORT__', '%s' % service[ 'port' ], cmd )

	# everything else gets expanded to values found in the macros dict
	for m in re.finditer( '(__\w+__)+', cmd ):
		for macroname in m.groups():
			if macroname in macros:
				cmd = re.sub( macroname, macros[ macroname ], cmd )
	return cmd


def list_services( info, nagios_host_object ):
	""" prepare a list of services on open ports and their nagios check_command counterparts.
	"""

	# step through all the services discovered by nmap
	checks = []
	for protocol_name in info.all_protocols():
		for port in info[ protocol_name ]:
			service = info[ protocol_name ][ port ]
			service['port'] = port

			# we only care about open ports
			if service[ 'state' ] != 'open':
				continue
			checks.append( get_nagios_check_for_nmap_service( service ) )

	# append the default checks
	to_add = []
	to_add.extend( common_checks['all'] )

	# add the OS-specific service checks 
	if 'os' in info and info['os']['family'] in common_checks:
		to_add.extend( common_checks[ info['os']['family'] ] )

	# append all the extra service checks
	for s in to_add:
		( n, cmd ) = s
		c = get_nagios_check_for_nmap_service( { 'name' : n, 'port' : 5666, }, cmd=cmd )
		c['nmap_name'] = 'nrpe'
		checks.append(c)

	# now we have a list of nagios service checks. We must determine whether or not 
	# the check_commands exist, and if we should be adding the service definitions 
	# to our host.
	services = []
	for check in checks:

		# check might be empty if the service is one we ignore
		if 'command_name' not in check:
			continue

		# don't add an entry for the NRPE port itself
		if check['service_desc'] == 'nrpe':
			continue

		if config['verbose']:

			# does this check command exist in nagios?
			cmd = nc.get_command( check['command_name'] )
			check['valid'] = False
			if  cmd:
				check['valid'] = True

			# does the host definition already exist, and does it contain this service?
			check['exists'] = False
			if nagios_host_object:
				s = nc.get_service( nagios_host_object['host_name'], check['service_desc'] )
				if s: 
					check['exists'] = True

		services.append(check)	

	# return the list of service dicts.
	return services


def parse_arguments():
	""" Parse command-line arguments.
	"""
	from optparse import OptionParser

	parser = OptionParser()
	parser.add_option( '-v', '--verbose', help='verbose output', action="store_true", dest="verbose" )
	parser.add_option( '-f','--config_file', dest="nagios_config", help="location of nagios.cfg", metavar="FILE")
	parser.add_option( '-t', '--nmap_target', dest="nmap_target", help="host(s) or network(s) to scan", metavar="TARGET")
	parser.add_option( '-o', '--nmap_options', dest="nmap_args", help='command-line options for nmap', metavar="ARGS" )
	parser.add_option( '-l', '--log', dest="logfile", help='error and debug log file', metavar="FILE" )

	parser.set_defaults(
		nmap_args     = '-O -sS -R --defeat-rst-ratelimit --host-timeout=300s -vv -d -p1-49151',
		nmap_target   = 'localhost',
		nagios_config = 'nagios.cfg',
		logfile       = 'nagiosnmapper.log'
	)
	(options, args) = parser.parse_args()
	o = options.__dict__
	o['nmap_args'] += ' -oN nmap.log'
	return o


def scan( target ):
	""" Initiate an nmap scan of a target
	"""
	nm.scan( target, 
			 arguments           = config['nmap_args'], 
			 callback            = one_scan_complete, 
			 scan_start_callback = scan_start, 
			 scan_end_callback   = scan_end  )

	# wait until the scan is complete, printing status updates as we go.
	timeout=30
	while nm.still_scanning():
		if nm._scan_start_time and time() - nm._scan_start_time >= timeout:
			raise RuntimeError, "nmap process timeout exceeded; terminating. %d" % nm._scan_start_time
		nm.wait(2)


def sort_ip_address_list( ips ):
	for i in range( len(ips) ):
		ips[i] = "%03d.%03d.%03d.%03d" % tuple( map( int, ips[i].split( '.' ) ) ) 

	ips.sort()
	return ips


def sort_listscan( target ):
	""" Return a sorted list of IP addresses that we will scan.
	"""

	sorted_targets = sort_ip_address_list( nm._nm.listscan( target ) )
	
	# weed out any host we're ignoring by doing a DNS lookup on each target
	# and checking to see if it's listed in ingore_hosts.
	if ignored_hosts:
		weeded = []
		for addr in sorted_targets:
			name=''
			aliases=[]
			addresses=[]
			try:
				( name, aliases, addresses ) = socket.gethostbyaddr( addr )
			except:
				pass
			if name and name in ignored_hosts:
				continue
			weeded.append( addr )
			sorted_targets = weeded

	return sorted_targets


def main():
	""" main program loop.
	"""

	# redirect stderr to a file so it doesn't mess up formatted output
	if config['verbose']:
		print sys.argv[0], 'starting up. Errors logged to', config['logfile']
	sys.stderr = open( config['logfile'], 'w' )

	start_time = time()

	# if nmap_target is a list, scan each target in turn.
	# Otherwise, scan the whole target at once
	if type( config['nmap_target'] ) is types.ListType:
		completed=0
		for target in config['nmap_target']:
			scan(target)
			completed+=1

		# print a scan summary
		total_time = time() - start_time
		if config['verbose']:
			print "STATUS indicators:"
			print "  (!) = Missing check_command definition for this service"
			print "  (*) = Service definition already exists on this host"
			print "Done. %d of %d hosts scanned in %s." % ( completed, host_count, str( timedelta( seconds = total_time ) ) )
		if completed != host_count:
			print "WARNING: Scan ended prematurely; check log for errors."

	else:
		# define post-scan actions, printed summaries, etc. in the scan_end() callback function
		scan( config['nmap_target'] )


if __name__ == '__main__':

	# create the nmap scanner
	try:
		nm = nmap.PortScannerAsync()
	except nmap.PortScannerError:
		print('Nmap not found', sys.exc_info()[0])
		sys.exit(-1)
	except:
		raise

	config = parse_arguments()

	# create the nagios parser
	nc = Parsers.config( config['nagios_config'] )
	nc.extended_parse()

	# transform the specified target (which could be an entire network, a block, etc)
	# into a sorted list of IP addresses.  This allows the user to resume a long scan 
	# if it has to be interrupted, or crashes, or times out and so forth.
	#
	config['nmap_target']  = sort_listscan( config['nmap_target'] )
	host_count = len( config['nmap_target'] )

	main()

