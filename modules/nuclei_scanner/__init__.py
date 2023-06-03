#!/usr/bin/env python3
#
# from httpscan import *
# data_list = nuclei_scan('https://example.com')

import subprocess
import json
import random
import os
from modules.logging import *

def nuclei_json_file_reader(file):
	try:
		f = open(file)
		fcontents = f.read()
		f.close()
		items = []
		for fcontent in fcontents.split('\n'):
			try:
				data = json.loads(fcontent)
				timestamp = data['timestamp']
				try:
					del data['timestamp']
				except Exception:
					pass
				try:
					del data['template-url']
				except Exception:
					pass
				try:
					del data['template-path']
				except Exception:
					pass
				try:
					del data['info']['author']
				except Exception:
					pass
				try:
					del data['template']
				except Exception:
					pass
				try:
					del data['curl-command']
				except Exception:
					pass
				items.append(data)
			except Exception:
				pass
		return items
	except Exception:
		logger.error(traceback.format_exc())
		return False

def nuclei_scan(TARGET):
	try:
		NUCLEI_BIN = os.getenv('NUCLEI_BIN', '/go/bin/nuclei')
		RESULT_FILE = '/tmp/nuclei-{SCAN_ID}.json'.format(SCAN_ID=random.randint(1000000, 9999999))
		subprocess.run(['{NUCLEI_BIN}'.format(NUCLEI_BIN=NUCLEI_BIN), '-u', '{TARGET}'.format(TARGET=TARGET), '-retries', '3', '-jsonl', '-o', '{RESULT_FILE}'.format(RESULT_FILE=RESULT_FILE)], capture_output=True, text=True)
		result = nuclei_json_file_reader(RESULT_FILE)
		os.unlink(RESULT_FILE)
		return result
	except Exception:
		logger.error(traceback.format_exc())
		return False
