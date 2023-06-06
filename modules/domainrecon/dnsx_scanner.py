#!/usr/bin/env python3

from modules.logging import *
import subprocess
import json
import os

def dnsx_scan(target):
	try:
		DNSX_BIN = os.getenv('DNSX_BIN', '/go/bin/dnsx')
		domain = subprocess.Popen(["echo", "{target}".format(target=target)], stdout=subprocess.PIPE)
		get_dns = subprocess.run(['{}'.format(DNSX_BIN), '-a', '-aaaa', '-cname', '--resp', '-retry', '3', '-json', '-silent'], stdin=domain.stdout, capture_output=True, text=True)
		try:
			data = json.loads(get_dns.stdout)
		except Exception:
			return False
		timestamp = data['timestamp']
		del data['timestamp']
		del data['resolver']
		del data['all']
		if data == None:
			return False
		return data
	except Exception:
		logger.error(traceback.format_exc())
		return False