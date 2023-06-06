#!/usr/bin/env python3

from modules.logging import *
import xmltodict
import json
import subprocess
import os
import random

def nmap_service_scan(target, portcsv):
	try:
		NMAP_BIN = os.getenv('NMAP_BIN', '/usr/bin/nmap')
		XML_OUTPUT = '/tmp/nmap-service-scan-{rand}{rand2}.xml'.format(rand=random.randint(10000, 99999), rand2=random.randint(10000, 99999))
		subprocess.run(['{}'.format(NMAP_BIN), '-p', '{}'.format(portcsv), '-Pn', '-sV', '-oX', '{XML_OUTPUT}'.format(XML_OUTPUT=XML_OUTPUT), '{target}'.format(target=target), '--open'], capture_output=True, text=True)
		xml_file = open(XML_OUTPUT)
		xml_content = xml_file.read()
		xml_file.close()
		os.unlink(XML_OUTPUT)
		ports = xmltodict.parse(xml_content)['nmaprun']['host']
		ports = dict(ports['ports'])['port']
		results = []
		for port in ports:
			try:
				port['status'] = port['state']
				del port['state']
				port['protocol'] = port['@protocol']
				del port['@protocol']
				port['port'] = port['@portid']
				del port['@portid']
				port['address'] =  target
				port = dict(reversed(list(port.items())))
				results.append(port)
			except Exception:
				pass
		return results
	except Exception:
		logger.error(traceback.format_exc())
		return False