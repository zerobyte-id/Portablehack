#!/usr/bin/env python3

import requests
from modules.logging import *
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

def test_http_connection(url):
	if url.startswith("https://"):
		try:
			response = requests.get(url, verify=False, timeout=10)
			return True
		except Exception:
			return False
	elif url.startswith("http://"):
		try:
			response = requests.get(url, timeout=10)
			return True
		except Exception:
			return False
	else:
		return False

def validatehttp(host):
	try:
		if not host.startswith("http://") and not host.startswith("https://"):
			if test_http_connection('https://' + host) == True:
				host_for_test = 'https://' + host
				http = urlparse(host_for_test)
				if http.scheme == 'https' and http.port == 443:
					http = http.scheme + '://' + http.hostname
				else:
					http = http.scheme + '://' + http.netloc
				return http
			elif test_http_connection('http://' + host) == True:
				host_for_test = 'http://' + host
				http = urlparse(host_for_test)
				if http.scheme == 'http' and http.port == 80:
					http = http.scheme + '://' + http.hostname
				else:
					http = http.scheme + '://' + http.netloc
				return http
			else:
				return False

		else:
			http = urlparse(host)
			if http.netloc == '':
				logger.error(traceback.format_exc())
				return False
			if http.scheme == 'http' and http.port == 80:
				http = http.scheme + '://' + http.hostname
			elif http.scheme == 'https' and http.port == 443:
				http = http.scheme + '://' + http.hostname
			else:
				http = http.scheme + '://' + http.netloc
			test_connection = test_http_connection(http)
			if test_connection == True:
				return http
			else:
				return False
	except:
		logger.error(traceback.format_exc())
		return False