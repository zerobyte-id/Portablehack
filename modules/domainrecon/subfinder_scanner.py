#!/usr/bin/env python3

import os
from modules.logging import *
import subprocess

def subfinder_scan(target):
	try:
		SUBFINDER_BIN = os.getenv('SUBFINDER_BIN', '/go/bin/subfinder')
		subfinder_run = subprocess.check_output(['{}'.format(SUBFINDER_BIN), '-d', '{}'.format(target), '-recursive', '-silent'])
		subdomains = []
		for subdomain in subfinder_run.decode('ascii').split():
			subdomains.append(subdomain)
		subdomains.append(target)
		subdomains_parse = []
		[ subdomains_parse.append(subdomain) for subdomain in subdomains if subdomain not in subdomains_parse ]
		return subdomains_parse
	except Exception:
		logger.error(traceback.format_exc())
		return False