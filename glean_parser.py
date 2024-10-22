from __future__ import division
from __future__ import print_function
from six import iteritems
from six.moves import input
from textwrap import TextWrapper
from getpass import getpass
from collections import defaultdict
from datetime import datetime
import warnings
import time
import pexpect
import logging
import subprocess
import json
import sys
import os
import re

SCRIPT_VERSION = "v1.2.1"
node_regex = r'topology/pod-(?P<pod>\d+)/node-(?P<node>\d+)'
ver_regex = r'(?:dk9\.)?[1]?(?P<major1>\d)\.(?P<major2>\d)(?:\.|\()(?P<maint>\d+)\.?(?P<patch>(?:[a-b]|[0-9a-z]+))\)?'

tz = time.strftime('%z')
ts = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
DIR = 'glean_parser_logs/'
SWITCH_DIR = DIR + 'switches/'
BUNDLE_NAME = 'glean_parser_%s%s.tgz' % (ts, tz)
RESULT_FILE = DIR + 'glean_parser_%s%s.txt' % (ts, tz)
JSON_FILE = DIR + 'glean_parser_%s%s.json' % (ts, tz)
LOG_FILE = DIR + 'glean_parser_debug.log'
fmt = '[%(asctime)s.%(msecs)03d{} %(levelname)-8s %(funcName)20s:%(lineno)-4d] %(message)s'.format(tz)
subprocess.check_output(['mkdir', '-p', DIR])
subprocess.check_output(['mkdir', '-p', SWITCH_DIR])
logging.basicConfig(level=logging.DEBUG, filename=LOG_FILE, format=fmt, datefmt='%Y-%m-%d %H:%M:%S')
warnings.simplefilter(action='ignore', category=FutureWarning)


class Connection(object):
	"""
	Object built primarily for executing commands on Cisco IOS/NXOS devices.  The following
	methods and variables are available for use in this class:

		username		 (opt) username credential (default 'admin')
		password		 (opt) password credential (default 'cisco')
		enable_password	 (opt) enable password credential (IOS only) (default 'cisco')
		protocol		 (opt) telnet/ssh option (default 'ssh')
		port			 (opt) port to connect on (if different from telnet/ssh default)
		timeout			 (opt) wait in seconds between each command (default 30)
		prompt			 (opt) prompt to expect after each command (default for IOS/NXOS)
		log				 (opt) logfile (default None)
		verify			 (opt) verify/enforce strictHostKey values for SSL (disabled by default)
		searchwindowsize (opt) maximum amount of data used in matching expressions
							   extremely important to set to a low value for large outputs
							   pexpect default = None, setting this class default=256
		force_wait		 (opt) some OS ignore searchwindowsize and therefore still experience high
							   CPU and long wait time for commands with large outputs to complete.
							   A workaround is to sleep the script instead of running regex checking
							   for prompt character.
							   This should only be used in those unique scenarios...
							   Default is 0 seconds (disabled).	 If needed, set to 8 (seconds)

		functions:
		connect()		 (opt) connect to device with provided protocol/port/hostname
		login()			 (opt) log into device with provided credentials
		close()			 (opt) close current connection
		cmd()			 execute a command on the device (provide matches and timeout)

	Example using all defaults
		c = Connection("10.122.140.89")
		c.cmd("terminal length 0")
		c.cmd("show version")
		print "version of code: %s" % c.output

	@author agossett@cisco.com
	@version 07/28/2014
	"""

	def __init__(self, hostname):
		self.hostname = hostname
		self.log = None
		self.username = 'admin'
		self.password = 'cisco'
		self.enable_password = 'cisco'
		self.protocol = "ssh"
		self.port = None
		self.timeout = 30
		self.prompt = "[^#]#[ ]*(\x1b[\x5b-\x5f][\x40-\x7e])*[ ]*$"
		self.verify = False
		self.searchwindowsize = 256
		self.force_wait = 0
		self.child = None
		self.output = ""  # output from last command
		self._term_len = 0	# terminal length for cisco devices
		self._login = False	 # set to true at first successful login
		self._log = None  # private variable for tracking logfile state

	def __connected(self):
		# determine if a connection is already open
		connected = (self.child is not None and self.child.isatty())
		logging.debug("check for valid connection: %r" % connected)
		return connected

	@property
	def term_len(self):
		return self._term_len

	@term_len.setter
	def term_len(self, term_len):
		self._term_len = int(term_len)
		if (not self.__connected()) or (not self._login):
			# login function will set the terminal length
			self.login()
		else:
			# user changing terminal length during operation, need to explicitly
			self.cmd("terminal length %s" % self._term_len)

	def start_log(self):
		""" start or restart sending output to logfile """
		if self.log is not None and self._log is None:
			# if self.log is a string, then attempt to open file pointer (do not catch exception, we want it
			# to die if there's an error opening the logfile)
			if isinstance(self.log, str) or isinstance(self.log, unicode):
				self._log = open(self.log, "ab")
			else:
				self._log = self.log
			logging.debug("setting logfile to %s" % self._log.name)
			if self.child is not None:
				self.child.logfile = self._log

	def stop_log(self):
		""" stop sending output to logfile """
		self.child.logfile = None
		self._log = None
		return

	def connect(self):
		# close any currently open connections
		self.close()

		# determine port if not explicitly set
		if self.port is None:
			if self.protocol == "ssh":
				self.port = 22
			if self.protocol == "telnet":
				self.port = 23
		# spawn new thread
		if self.protocol.lower() == "ssh":
			logging.debug(
				"spawning new pexpect connection: ssh %s@%s -p %d" % (self.username, self.hostname, self.port))
			no_verify = " -o StrictHostKeyChecking=no -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null"
			no_verify += " -o HostKeyAlgorithms=+ssh-dss"
			if self.verify: no_verify = ""
			self.child = pexpect.spawn("ssh %s %s@%s -p %d" % (no_verify, self.username, self.hostname, self.port),
									   searchwindowsize=self.searchwindowsize)
		elif self.protocol.lower() == "telnet":
			logging.info("spawning new pexpect connection: telnet %s %d" % (self.hostname, self.port))
			self.child = pexpect.spawn("telnet %s %d" % (self.hostname, self.port),
									   searchwindowsize=self.searchwindowsize)
		else:
			logging.error("unknown protocol %s" % self.protocol)
			raise Exception("Unsupported protocol: %s" % self.protocol)

		# start logging
		self.start_log()

	def close(self):
		# try to gracefully close the connection if opened
		if self.__connected():
			logging.info("closing current connection")
			self.child.close()
		self.child = None
		self._login = False

	def __expect(self, matches, timeout=None):
		"""
		receives a dictionary 'matches' and returns the name of the matched item
		instead of relying on the index into a list of matches.	 Automatically
		adds following options if not already present
			"eof"		: pexpect.EOF
			"timeout"	: pexpect.TIMEOUT
		"""

		if "eof" not in matches:
			matches["eof"] = pexpect.EOF
		if "timeout" not in matches:
			matches["timeout"] = pexpect.TIMEOUT

		if timeout is None: timeout = self.timeout
		indexed = []
		mapping = []
		for i in matches:
			indexed.append(matches[i])
			mapping.append(i)
		result = self.child.expect(indexed, timeout)
		logging.debug("timeout: %d, matched: '%s'\npexpect output: '%s%s'" % (
			timeout, self.child.after, self.child.before, self.child.after))
		if result <= len(mapping) and result >= 0:
			logging.debug("expect matched result[%d] = %s" % (result, mapping[result]))
			return mapping[result]
		ds = ''
		logging.error("unexpected pexpect return index: %s" % result)
		for i in range(0, len(mapping)):
			ds += '[%d] %s\n' % (i, mapping[i])
		logging.debug("mapping:\n%s" % ds)
		raise Exception("Unexpected pexpect return index: %s" % result)

	def login(self, max_attempts=7, timeout=17):
		"""
		returns true on successful login, else returns false
		"""

		logging.debug("Logging into host")

		# successfully logged in at a different time
		if not self.__connected(): self.connect()
		# check for user provided 'prompt' which indicates successful login
		# else provide approriate username/password/enable_password
		matches = {
			"console": "(?i)press return to get started",
			"refuse": "(?i)connection refused",
			"yes/no": "(?i)yes/no",
			"username": "(?i)(user(name)*|login)[ as]*[ \t]*:[ \t]*$",
			"password": "(?i)password[ \t]*:[ \t]*$",
			"enable": ">[ \t]*$",
			"prompt": self.prompt
		}

		last_match = None
		while max_attempts > 0:
			max_attempts -= 1
			match = self.__expect(matches, timeout)
			if match == "console":	# press return to get started
				logging.debug("matched console, send enter")
				self.child.sendline("\r\n")
			elif match == "refuse":	 # connection refused
				logging.error("connection refused by host")
				return False
			elif match == "yes/no":	 # yes/no for SSH key acceptance
				logging.debug("received yes/no prompt, send yes")
				self.child.sendline("yes")
			elif match == "username":  # username/login prompt
				logging.debug("received username prompt, send username")
				self.child.sendline(self.username)
			elif match == "password":
				# don't log passwords to the logfile
				self.stop_log()
				if last_match == "enable":
					# if last match was enable prompt, then send enable password
					logging.debug("matched password prompt, send enable password")
					self.child.sendline(self.enable_password)
				else:
					logging.debug("matched password prompt, send password")
					self.child.sendline(self.password)
				# restart logging
				self.start_log()
			elif match == "enable":
				logging.debug("matched enable prompt, send enable")
				self.child.sendline("enable")
			elif match == "prompt":
				logging.debug("successful login")
				self._login = True
				# force terminal length at login
				self.term_len = self._term_len
				return True
			elif match == "timeout":
				logging.debug("timeout received but connection still opened, send enter")
				self.child.sendline("\r\n")
			last_match = match
		# did not find prompt within max attempts, failed login
		logging.error("failed to login after multiple attempts")
		return False

	def cmd(self, command, **kargs):
		"""
		execute a command on a device and wait for one of the provided matches to return.
		Required argument string command
		Optional arguments:
			timeout - seconds to wait for command to completed (default to self.timeout)
			sendline - boolean flag to use send or sendline fuction (default to true)
			matches - dictionary of key/regex to match against.	 Key corresponding to matched
				regex will be returned.	 By default, the following three keys/regex are applied:
					'eof'		: pexpect.EOF
					'timeout'	: pexpect.TIMEOUT
					'prompt'	: self.prompt
			echo_cmd - boolean flag to echo commands sent (default to false)
				note most terminals (i.e., Cisco devices) will echo back all typed characters
				by default.	 Therefore, enabling echo_cmd may cause duplicate cmd characters
		Return:
		returns the key from the matched regex.	 For most scenarios, this will be 'prompt'.	 The output
		from the command can be collected from self.output variable
		"""

		sendline = True
		timeout = self.timeout
		matches = {}
		echo_cmd = False
		if "timeout" in kargs:
			timeout = kargs["timeout"]
		if "matches" in kargs:
			matches = kargs["matches"]
		if "sendline" in kargs:
			sendline = kargs["sendline"]
		if "echo_cmd" in kargs:
			echo_cmd = kargs["echo_cmd"]

		# ensure prompt is in the matches list
		if "prompt" not in matches:
			matches["prompt"] = self.prompt

		self.output = ""
		# check if we've ever logged into device or currently connected
		if (not self.__connected()) or (not self._login):
			logging.debug("no active connection, attempt to login")
			if not self.login():
				raise Exception("failed to login to host")

		# if echo_cmd is disabled, then need to disable logging before
		# executing commands
		if not echo_cmd: self.stop_log()

		# execute command
		logging.debug("cmd command: %s" % command)
		if sendline:
			self.child.sendline(command)
		else:
			self.child.send(command)

		# remember to re-enable logging
		if not echo_cmd: self.start_log()

		# force wait option
		if self.force_wait != 0:
			time.sleep(self.force_wait)

		result = self.__expect(matches, timeout)
		self.output = "%s%s" % (self.child.before, self.child.after)
		if result == "eof" or result == "timeout":
			logging.warning("unexpected %s occurred" % result)
		return result


class IPAddress:
	"""Custom IP handling class since old APICs do not have `ipaddress` module.
	"""
	@staticmethod
	def ip_to_binary(ip):
		octets = ip.split(".")
		octets_bin = [format(int(octet), "08b") for octet in octets]
		return "".join(octets_bin)

	@classmethod
	def get_network_binary(cls, ip, pfxlen):
		ip_bin = cls.ip_to_binary(ip)
		return ip_bin[0:32-(32-int(pfxlen))]

	@classmethod
	def ip_in_subnet(cls, ip, subnet):
		subnet_ip, subnet_pfxlen = subnet.split("/")
		subnet_network = cls.get_network_binary(subnet_ip, subnet_pfxlen)
		ip_network = cls.get_network_binary(ip, subnet_pfxlen)
		return ip_network == subnet_network

class AciVersion():
	v_regex = r'(?:dk9\.)?[1]?(?P<major1>\d)\.(?P<major2>\d)(?:\.|\()(?P<maint>\d+)\.?(?P<patch>(?:[a-b]|[0-9a-z]+))\)?'

	def __init__(self, version):
		self.original = version
		v = re.search(self.v_regex, version)
		self.version = ('{major1}.{major2}({maint}{patch})'
						.format(**v.groupdict()) if v else None)
		self.dot_version = ("{major1}.{major2}.{maint}{patch}"
							.format(**v.groupdict()) if v else None)
		self.simple_version = ("{major1}.{major2}({maint})"
							   .format(**v.groupdict()) if v else None)
		self.major1 = v.group('major1') if v else None
		self.major2 = v.group('major2') if v else None
		self.maint = v.group('maint') if v else None
		self.patch = v.group('patch') if v else None
		self.regex = v
		if not v:
			raise RuntimeError("Parsing failure of ACI version `%s`", version)

	def __str__(self):
		return self.version

	def older_than(self, version):
		v = re.search(self.v_regex, version)
		if not v: return None
		for i in range(1, len(v.groups())+1):
			if i < 4:
				if int(self.regex.group(i)) > int(v.group(i)): return False
				elif int(self.regex.group(i)) < int(v.group(i)): return True
			if i == 4:
				if self.regex.group(i) > v.group(i): return False
				elif self.regex.group(i) < v.group(i): return True
		return False

	def newer_than(self, version):
		return not self.older_than(version) and not self.same_as(version)

	def same_as(self, version):
		v = re.search(self.v_regex, version)
		ver = ('{major1}.{major2}({maint}{patch})'
			   .format(**v.groupdict()) if v else None)
		return self.version == ver

def format_table(headers, data,
				 min_width=5, left_padding=2, hdr_sp='-', col_sp='	'):
	""" get string results in table format
	Args:
		header (list): list of column headers (optional)
				each header can either be a string representing the name or a
				dictionary with following attributes:
				{
					name (str): column name
					width (int or str): integer width of column. can also be a string 'auto'
										which is based on the longest string in column
					max_width (int): integer value of max width when combined with
				}
		data (list): list of rows, where each row is a list of values
					 corresponding to the appropriate header. If length of row
					 exceeds length of headers, it is is ignored.
		min_width (int, optional): minimum width enforced on any auto-calculated column. Defaults to 5.
		left_padding (int, optional): number of spaces to 'pad' left most column. Defaults to 2.
		hdr_sp (str, optional): print a separator string between hdr and data row. Defaults to '-'.
		col_sp (str, optional): print a separator string between data columns. Defaults to '  '.
	Returns:
		str: table with columns aligned with spacing
	"""
	if type(data) is not list or len(data) == 0:
		return ""
	cl = 800
	col_widths = []
	rows = []

	def update_col_widths(idx, new_width):
		if len(col_widths) < idx + 1:
			col_widths.append(new_width)
		elif col_widths[idx] < new_width:
			col_widths[idx] = new_width

	for row in data:
		if type(row) is not list:
			return ""
		for idx, col in enumerate(row):
			update_col_widths(idx, len(str(col)))
		rows.append([str(col) for col in row])
	h_cols = []
	for idx, col in enumerate(headers):
		if isinstance(col, str):
			update_col_widths(idx, len(col))
			h_cols.append({'name': col, 'width': 'auto'})
		elif isinstance(col, dict):
			name = col.get('name', '')
			width = col.get('width', '')
			max_w = col.get('max_width', 0)
			update_col_widths(idx, len(name))
			if width == 'auto' and max_w:
				try:
					if int(max_w) < col_widths[idx]:
						col_widths[idx] = int(max_w)
				except ValueError:
					max_w = 0
			else:
				try:
					col_widths[idx] = int(width)
				except ValueError:
					width = 'auto'
			h_cols.append({'name': name, 'width': width})

	# Adjust column width to fit the table with
	recovery_width = 3 * min_width
	total_width = sum(col_widths) + len(col_sp) * len(col_widths) + left_padding
	for idx, h in enumerate(h_cols):
		if total_width <= cl: break
		if h['width'] == 'auto' and col_widths[idx] > recovery_width:
			total_width -= col_widths[idx] - recovery_width
			col_widths[idx] = recovery_width

	pad = ' ' * left_padding
	output = []
	if headers:
		output.append(
			get_row(col_widths, [c['name'] for c in h_cols], col_sp, pad)
		)
		if isinstance(hdr_sp, str):
			if len(hdr_sp) > 0:
				hsp_sp = hdr_sp[0]	# only single char for hdr_sp
			values = [hsp_sp * len(c['name']) for c in h_cols]
			output.append(
				get_row(col_widths, values, col_sp, pad)
			)
	for row in rows:
		output.append(get_row(col_widths, row, col_sp, pad))
	return '\n'.join(output)


def get_row(widths, values, spad="	", lpad=""):
	cols = []
	row_maxnum = 0
	for i, value in enumerate(values):
		w = widths[i] if widths[i] > 0 else 1
		tw = TextWrapper(width=w)
		lines = []
		for v in value.split('\n'):
			lines += tw.wrap(v)
		cols.append({'width': w, 'lines': lines})
		if row_maxnum < len(lines): row_maxnum = len(lines)
	spad2 = ' ' * len(spad)	 # space separators except for the 1st line
	output = []
	for i in range(row_maxnum):
		row = []
		for c in cols:
			if len(c['lines']) > i:
				row.append('{:{}}'.format(c['lines'][i], c['width']))
			else:
				row.append('{:{}}'.format('', c['width']))
		if not output:
			output.append("%s%s" % (lpad, spad.join(row).rstrip()))
		else:
			output.append("%s%s" % (lpad, spad2.join(row).rstrip()))
	return ('\n'.join(output).rstrip())


def prints(objects, sep=' ', end='\n'):
	with open(RESULT_FILE, 'a') as f:
		print(objects, sep=sep, end=end, file=sys.stdout)
		print(objects, sep=sep, end=end, file=f)
		sys.stdout.flush()
		f.flush()


def print_title(title, index=None, total=None):
	if index and total:
		prints('[Check{:3}/{}] {}... '.format(index, total, title), end='')
	else:
		prints('{:14}{}... '.format('', title), end='')


def print_result(title, result, msg='',
				 headers=None, data=None,
				 unformatted_headers=None, unformatted_data=None,
				 recommended_action='',
				 doc_url='',
				 adjust_title=False):
	padding = 120 - len(title) - len(msg)
	if adjust_title: padding += len(title) + 18
	output = '{}{:>{}}'.format(msg, result, padding)
	if data:
		data.sort()
		output += '\n' + format_table(headers, data)
	if unformatted_data:
		unformatted_data.sort()
		output += '\n' + format_table(unformatted_headers, unformatted_data)
	if data or unformatted_data:
		output += '\n'
		if recommended_action:
			output += '\n  Recommended Action: %s' % recommended_action
		if doc_url:
			output += '\n  Reference Document: %s' % doc_url
		output += '\n' * 2
	prints(output)


def icurl(apitype, query):
	if apitype not in ['class', 'mo']:
		print('invalid API type - %s' % apitype)
		return []
	uri = 'http://127.0.0.1:7777/api/{}/{}'.format(apitype, query)
	cmd = ['icurl', '-gs', uri]
	logging.info('cmd = ' + ' '.join(cmd))
	response = subprocess.check_output(cmd)
	logging.debug('response: ' + str(response))
	imdata = json.loads(response)['imdata']
	if imdata and "error" in imdata[0].keys():
		raise Exception('API call failed! Check debug log')
	else:
		return imdata
		
		
def get_credentials():
	while True:
		usr = input('Enter username for APIC login			: ')
		if usr: break
	while True:
		pwd = getpass('Enter password for corresponding User  : ')
		if pwd: break
	print('')
	return usr, pwd
 
 
def output_to_file(switch_name, objects):
	#Function that takes the name of switch (switch_name) and cmd output (objects) 
	# then it writes the ouput to a txt file with the name of switch.
	switch_result_file =  SWITCH_DIR + switch_name + 'glean_parser_%s%s.txt' % (ts, tz)
	with open(switch_result_file, 'w') as f:
		lines = objects.split("\\r\\n")
		for line in lines:
			f.write(line+"\n")
		f.close()
		return switch_result_file


def readEventTime(textFile, lastevent = False, startline=1, endline=3):
	#Fuction that takes a textFile with log events and returns the timestamp or first or last event
	event = []
	try:
		with open(textFile) as f:
			lines= f.readlines()
			if lastevent:
				startline = len(lines) - 5
				endline = len(lines) - 3
			for line in lines[startline:endline]:
				event.append(line)
		for event_ts in event:
			try:
				time_str = event_ts.split(' at ')
				time_ts = datetime.strptime(time_str[1][0:25] , '%Y-%m-%dT%H:%M:%S.%f')
				if time_ts:
					f.close()
					return time_ts					 
			except Exception as e:
				continue	
	except Exception as e:
		return		

		
def readGleanEvent(textFile):
	#Function that takes a textfile, it filters the Glean Events, removes strings 
	# and return a list of glean Src and Dst IP addresses
	glean_event = []
	try:
		with open(textFile) as f:
			lines= f.readlines()
			for line in lines:
				if re.search('Received glean packet is an IP packet', line):
					new_line = re.sub(';info.*','',line)
					new_line = re.sub('.*glean;','',new_line)
					if not re.search('Vlan', new_line): #Removing unwated matches.
						glean_event.append(new_line)
			
			f.close()	
			return	glean_event 
			
	except Exception as e:
		return

def countAndSortEntries(event_list):
	# Function that takes a dictionary of events like: {'EVENT' : Number or instances}
	#  and returns a sorted list like [Number of instance, 'EVENT']
	output_dict = {i:event_list.count(i) for i in event_list}
	sorted_output = sorted(output_dict.items(), key=lambda x:x[1], reverse=True)
	return sorted_output

def countIPAddress(event_list, source = False, destination = False):
	#	Function that creates and returns a list of Destination, Source or Conversations. 
	ip_list = []
	for event in event_list:
		ips = event.split(';')
		if source:
			ip_list.append(ips[0])
		elif destination:
			ip_list.append(ips[1])
		else:
			
			ip_list.append(event)
	
	return ip_list

def printTopTen(node_name, node_id , glean_events, source = False , destination = False ): 
	#	Fuction that prints the 1st 10 Sorted items from a list.
	#	Function can print by Source , Destination or Conversation. 
	data = []
	#CONVERSATIONS 
		###	 source = False , destination = False
	category = 'Conversations'
	#DESTINATIONS 
		###	 source = False , destination = True
	if not source and destination:
		category = 'Destinations'
	#SOURCES 
		###	 source = True , destination = False
	if not destination and source:
		category = 'Sources'
	
	event = countIPAddress( glean_events,  source , destination)
	sorted_events = countAndSortEntries(event)
	prints('Top 10 Glean %s' % category)
	data.append('Top 10 Glean %s' % category)
	prints('#Events				IP Address')
	data.append('#Events				IP Address')
	for ip, num in sorted_events[0:10]:
		prints('%s		%s' % (num, ip))
		data.append('%s			%s' % (num, ip))
			
def switchOutputCollection(node_name, node_id , filename):
	#Function that takes a three variables, for Node Name ID and Filename with ARP output
	# and Checks for the 1st and Last ARP event to get delta between them.
	#It takes the number of glean events from arp output and then divides
	# between the time delta to get the glean rate seen in the Switch.
	#If there are more than 10 Glean requests seen, the function calls for the
	# Top ten Sources, Destination and Conversations seen.	
	title = 'Parsing ARP Event Output from Nodes for Node %s ' % node_name 
	msg = ''
	data = []
	print_title(title)
	print("\n")
	prints('======= Leaf %s	 ========' % (node_name) )
	data.append('======= Leaf %s  ========' % (node_name) )
	firstEvent = readEventTime(filename)
	lastEvent = readEventTime(filename, lastevent=True)
	try:
		timedelta =	 firstEvent - lastEvent
		prints('Glean Start time: %s  Glean End time:	%s Time Delta: %s seconds' % (lastEvent,firstEvent, timedelta.total_seconds()))
		data.append('Glean Start time: %s  Glean End time:	%s Time Delta: %s seconds' % (lastEvent,firstEvent, timedelta.total_seconds()))
		glean_events = readGleanEvent(filename)
		rate= len(glean_events) / timedelta.total_seconds()
		prints('Number of Glean Events: %s	Glean rate: %s' % ( len(glean_events) , str(rate)))
		data.append('Number of Glean Events: %s	 Glean rate: %s' % ( len(glean_events) , str(rate)))
		if len(glean_events) > 10:
			#Sources
			printTopTen(node_name, node_id , glean_events, source = True , destination = False)
			#Destinations
			printTopTen(node_name, node_id , glean_events, source = False , destination = True)
			#Conversations
			printTopTen(node_name, node_id , glean_events)
		else:
			print('Not enought Glean Events to parse')
	except Exception as e:
			timedelta = 'Delta Not Found'
			prints('Issue with Node ID %s Name %s ' % (node_id, node_name))
			data.append([node_name, '-', '-', '-', e])
			prints(e)
			
			
def readNodeList(outputList):
	#Gets a List variable with [node Name, Node ID , Output File name]
	# and runs the SwitchOutputCollection functio on each
	title = 'Parsing ARP Event Output from Nodes'
	print_title(title)
	print("\n")
	for node_name, node_id , filename in outputList:
		switchOutputCollection(node_name, node_id , filename)


def copp_switch_cli_connection(leaf,**kwargs):
	# This function gets the Copp Stats command and returns the redpackets for the glean class
	title = 'Connecting to Leaf and getting glean drops'
	headers = ['Pod-ID', 'Node-ID', 'State', 'Recommended Action']
	data = []
	output_files = []
	node_title = 'Checking %s...' % str(leaf)
	try:
		c = Connection(leaf)
		c.username = username
		c.password = password
		c.log = LOG_FILE
		c.connect()	  
	except Exception as e:
		data.append([leaf, '-', '-', '-', e])
	try:
		c.cmd("term len 0")
		c.cmd(
			'vsh_lc -c "show system internal aclqos brcm copp entries unit 0" | egrep "glean"', timeout = 10)
		output = c.output
		glean_stats = output.split()  
					 
	except Exception as e:
		data.append([leaf, '-', '-', '-', e])
		output = ''
		return	
	#return glean_start[29] for green packets, 30 for red packets , drops
	return glean_stats[30]	

def getDropDelta(leaf_ip, **kwargs):
	#	Function that gets the Glean drops twice from a Switch to get the delta for counters
	title = 'Getting Delta Drops for Glean traffic'
	data = []
	drop_delta = 0
	drops0 = copp_switch_cli_connection( leaf_ip, **inputs)
	if not drops0:
		return 0
	#	Wait three seconds between 1st and 2nd command output
	time.sleep(3)
	drops1 = copp_switch_cli_connection( leaf_ip, **inputs)
	if drops0 and drops1 :	
		drop_delta = int(drops1) - int(drops0) 
	else:
		return	0
	return drop_delta

def switch_list(**kwargs):
	# This function lists the Switches along with their Fabric Info. It reviews the glean rate
	# and glean drop delta, if there are drops increasing it adds them to a list with the Leaf information.
	title = 'Listing Active Leaf Switches in fabric'
	result ='FAIL_UF'
	msg = ''
	headers = ['Pod-ID', 'Node-ID', 'State', 'Recommended Action']
	data = []
	print_title(title)
	topSystems = icurl('class', 'topSystem.json?&query-target-filter=eq(topSystem.role,"leaf")')	
	print("\n")
	activeNodes = []
	for topSystem in topSystems:
		state = topSystem['topSystem']['attributes']['state']
		if state == 'out-of-service ':
			continue
		leafNodeId = icurl('class',
					 'fabricNode.json?&query-target-filter=and(eq(fabricNode.name,"%s"))' % topSystem['topSystem']['attributes']['name'])
		leaf_gen2 =	 re.search(r"\-[E|F]X",leafNodeId[0]['fabricNode']['attributes']['model'] )
		#IF LEAF is not gen2 continue
		if not leaf_gen2:
			continue
		#Only Gen-2 Leaf support copp command
		print('LEAF NAME		-		%s' % topSystem['topSystem']['attributes']['name'])
		print( 'LEAF ID			-		%s'% str(leafNodeId[0]['fabricNode']['attributes']['id']))
		print('LEAF ADDRESS		-		%s' % topSystem['topSystem']['attributes']['address'])
		coppClass = icurl('class',
					 'coppClass.json?&query-target-filter=and(eq(coppClass.dn,"%s/sys/copp/classp-glean"))' % leafNodeId[0]['fabricNode']['attributes']['dn'])
					 
		print('GLEAN RATE		-		%s' % coppClass[0]['coppClass']['attributes']['rate'])			
		glean_drop_delta = getDropDelta( topSystem['topSystem']['attributes']['address'], **inputs)
		print('GLEAN DROP DELTA		-		%s' %  glean_drop_delta)
		print('\n')
		if glean_drop_delta > 1:
			activeNodes.append([topSystem['topSystem']['attributes']['name'], leafNodeId[0]['fabricNode']['attributes']['id'], topSystem['topSystem']['attributes']['oobMgmtAddr']])
			
	if not topSystems:
		result = 'MANUAL'
		msg = 'Switch topSystem not found!'
	elif not data:
		result = 'PASS'
	print_result(title, result, msg, headers, data)
	return	activeNodes


def active_switch_cli_connection(activeNodes,**kwargs):
	#	Function that takes a list of nodes and username//password input
	#	it runs the show ip arp internal event-history event command and it saves the
	#	the output to a file, it returns a list with the file information for each leaf
	title = 'Connecting to ACTIVE Switches and fetching CLI output'
	result ='FAIL_UF'
	msg = ''
	headers = ['Pod-ID', 'Node-ID', 'State', 'Recommended Action']
	data = []
	output_files = []
	print_title(title)
	print("\n")
	for activeNodeName, activeNodeId, activeNodeIP	in activeNodes:
		node_title = 'Checking %s...' % str(activeNodeName)
		try:
			c = Connection(activeNodeIP)
			c.username = username
			c.password = password
			c.log = LOG_FILE
			c.connect()	  
		except Exception as e:
			data.append([activeNodeName, '-', '-', '-', e])
			print_result(node_title, e)
			continue
		try:
			c.cmd("term len 0")
			c.cmd(
				'show ip arp internal event-history event', timeout=120)
			output = c.output	
			filename = output_to_file(activeNodeName, output)
			output_files.append([activeNodeName, activeNodeIP , filename])
			data.append([activeNodeName, '-', '-', '-', 'Output retrieved'])
			print_result(title, result, msg, headers, data)				 
		except Exception as e:
			data.append([activeNodeName, '-', '-', '-', e])
			print_result(node_title, e)
			continue
	return output_files

######
######
##			MAIN Function, it asks for the user credentials, and checks for the active leaf
##				switches with glean drops , then it gets the arp event 
##				and glean rate and tops IPs for the switches with glean drops increasing
######
######
prints('	==== %s%s, Script Version %s  ====\n' % (ts, tz, SCRIPT_VERSION))
prints('!!!! Check https://gitlab-sjc.cisco.com/jeestrad/glean_parser for Latest Release !!!!\n')
prints('To use a non-default Login Domain, enter apic#DOMAIN\\\\USERNAME')
username, password = get_credentials()

inputs = {'username': username, 'password': password}
			  
activeNodes = switch_list(**inputs)
list_of_files=active_switch_cli_connection(activeNodes ,**inputs)
readNodeList(list_of_files)	