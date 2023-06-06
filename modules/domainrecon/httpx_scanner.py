#!/usr/bin/env python3

from modules.logging import *
from urllib.parse import urlparse
import subprocess
import json
import os

def httpx_parse(target):
	try:
		target = urlparse(target)
		if target.scheme == 'http' and target.port == 80:
			target = target.scheme + '://' + target.hostname
		elif target.scheme == 'https' and target.port == 443:
			target = target.scheme + '://' + target.hostname
		else:
			target = target.scheme + '://' + target.netloc
		return target
	except Exception:
		return None

def httpx_scan(target):
	try:
		HTTPX_BIN = os.getenv('HTTPX_BIN', '/go/bin/httpx')
		target = subprocess.Popen(["echo", "{target}".format(target=target)], stdout=subprocess.PIPE)
		get_http_list = subprocess.run(['{}'.format(HTTPX_BIN), '-timeout', '5', '-retries', '3', '-status-code', '-tech-detect', '-json', '-silent'], stdin=target.stdout, capture_output=True, text=True)
		result = []
		for http_list in get_http_list.stdout.split('\n'):
			if 'url' in http_list:
				data = json.loads(http_list)
				try:
					tech = data['tech']
				except Exception:
					tech = None
					pass
				try:
					content_type = data['content_type']
				except Exception:
					content_type = None
					pass
				data_parsed = {'url': httpx_parse(data['url']), 'status_code': data['status_code'], 'host': data['host'], 'port': data['port'], 'content_type': content_type, 'technologies': tech}
				result.append(data_parsed)
		if result == []:
			return False
		return result[0]
	except Exception:
		logger.error(traceback.format_exc())
		return False