#!/usr/bin/env python3

from modules.logging import *
import json
import subprocess
import os
import random

def naabu_scan(target):
	try:
		NAABU_BIN = os.getenv('NAABU_BIN', '/go/bin/naabu')
		JSON_OUTPUT = '/tmp/naabu-result-{}-{}.json'.format(random.randint(10000, 99999), random.randint(10000, 99999))
		naabu_result = subprocess.run(['{}'.format(NAABU_BIN), '-host', '{}'.format(target), '-p', '-', '-skip-host-discovery', '-c', '100', '-json', '-o', JSON_OUTPUT, '-debug', '-verbose'], capture_output=True, text=True)
		json_open = open(JSON_OUTPUT)
		json_content = json_open.read()
		json_open.close()
		json_ports = json_content.strip().split('\n')
		open_ports = []
		for row in json_ports:
			port = json.loads(row)['port']['Port']
			ip = json.loads(row)['ip']
			result = {'address': ip, 'port': port, 'status': 'open', 'protocol':'?', 'service':[{'@name': 'unknown'}]}
			open_ports.append(result)
		os.unlink(JSON_OUTPUT)
		return open_ports
	except Exception:
		logger.error(traceback.format_exc())
		return False