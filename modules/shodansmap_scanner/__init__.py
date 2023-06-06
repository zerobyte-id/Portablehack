#!/usr/bin/env python3

from modules.logging import *
import subprocess
import json
import os
import random

def shodansmap_scan(target):
	try:
		P_ID = str(random.randint(10000, 99999)) + '-' + str(random.randint(10000, 99999)) + '-' + str(random.randint(10000, 99999))
		SHODAN_SMAP_BIN = os.getenv('SHODAN_SMAP_BIN', '/go/bin/smap')
		JSON_OUTPUT = '/tmp/smap-shodan-{}.json'.format(P_ID)
		shodansmap_run = subprocess.run(['{}'.format(SHODAN_SMAP_BIN), '-sV', '{}'.format(target), '-oJ', JSON_OUTPUT], capture_output=True, text=True)
		json_open = open(JSON_OUTPUT)
		json_content = json_open.read()
		json_content = json.loads(json_content)
		json_open.close()
		os.unlink(JSON_OUTPUT)
		return json_content
	except Exception:
		logger.error(traceback.format_exc())
		return False
