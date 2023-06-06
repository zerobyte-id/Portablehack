#!/usr/bin/env python3

import warnings
from modules.validatehttp import *
from modules.nuclei_scanner import *
from modules.nmap_service_scanner import *
from modules.naabu_scanner import *
from modules.shodansmap_scanner import *
from modules.domainrecon.subfinder_scanner import *
from modules.domainrecon.dnsx_scanner import *
from modules.logging import *
from flask import Flask, request, jsonify, render_template, escape
from pymongo import MongoClient, UpdateOne, DESCENDING
import redis
import hashlib
import pytz
import datetime
import json
import os
import threading
import ipaddress
import yaml
import requests

warnings.filterwarnings("ignore")

### REDIS ENVIRONMENT - STARTS ###
try:
	REDIS_HOST = os.getenv('REDIS_HOST', 'redis-server')
	REDIS_PORT = os.getenv('REDIS_PORT', 6379)
	REDIS_PASS = os.getenv('REDIS_PASS', 'password')
	REDIS_DB = os.getenv('REDIS_DB', 0)
	REDIS_URI = 'redis://:{password}@{hostname}:{port}/{db}'.format(hostname=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS, db=REDIS_DB)
	redis_connect = redis.Redis.from_url(REDIS_URI)
except Exception:
	logger.error(traceback.format_exc())
	logger.error('REDIS WAS ERROR!')
	exit(1)
### REDIS ENVIRONMENT - ENDS ###

### MONGODEB ENVIRONMENT - STARTS ###
try:
	MONGODB_USER = os.getenv('MONGODB_USER', 'username')
	MONGODB_PASS = os.getenv('MONGODB_PASS', 'password')
	MONGODB_HOST = os.getenv('MONGODB_HOST', 'mongodb-server')
	MONGODB_PORT = os.getenv('MONGODB_PORT', 27017)
	MONGODB_NAME = os.getenv('MONGODB_NAME', 'portablehack')
	MONGODB_URI = 'mongodb://{username}:{password}@{hostname}:{port}/'.format(username=MONGODB_USER, password=MONGODB_PASS, hostname=MONGODB_HOST, port=int(MONGODB_PORT))
	mongo_client = MongoClient(MONGODB_URI)
	mongodb = mongo_client[MONGODB_NAME]
except Exception:
	logger.error(traceback.format_exc())
	logger.error('MONGODB WAS ERROR!')
	exit(1)
### MONGODEB ENVIRONMENT - ENDS ###

### WEBSERVICE ENVIRONMENT - STARTS ###
LISTEN_ADDR = os.getenv('LISTEN_ADDR', '0.0.0.0')
LISTEN_PORT = int(os.getenv('LISTEN_PORT', 5000))
APP_DEBUG = eval(os.getenv('APP_DEBUG', 'True'))
### WEBSERVICE ENVIRONMENT - ENDS ###

def now():
	TZ = pytz.timezone('Asia/Jakarta')
	datetimenow = datetime.datetime.now()
	datetimenow = datetimenow.replace(tzinfo=TZ, microsecond=0).isoformat()
	return datetimenow

def validateip(ip_addr):
	try:
		ip_object = ipaddress.ip_address(ip_addr)
		return True
	except ValueError:
		return False

def GetPortFromMongoCSV(target):
	try:
		mongo_get_port = mongodb['openports'].find({'address': target}, {'_id': False, 'port': True})
		ports = []
		[ ports.append(row['port']) for row in mongo_get_port ]
		ports = ','.join(str(port) for port in ports)
		return ports
	except Exception:
		logger.error(traceback.format_exc())
		return False

def SubdomainScan(target):
	try:
		subdomains = subfinder_scan(target)
		for subdomain in subdomains:
			try:
				dns = dnsx_scan(subdomain)
				if dns is not False:
					dns['_id'] = hashlib.md5(str('{}'.format(dns['host'])).encode()).hexdigest()
					dns['timestamp'] = now()
					mongodb['list_domains'].update_one({"_id": dns['_id']}, {"$set": dns}, upsert=True)
			except Exception:
				pass
		redis_connect.delete('domainrecon-process-running:{target}'.format(target=target))
		return True
	except Exception:
		redis_connect.delete('domainrecon-process-running:{target}'.format(target=target))
		return False

def NmapServiceScan(target, portcsv):
	try:
		results = nmap_service_scan(target, portcsv)
		for result in results:
			try:
				result['_id'] = hashlib.md5(str(result['address'] + ':' + str(result['port'])).encode()).hexdigest()
				result['timestamp'] = now()
				mongodb['openports'].update_one({"_id": result['_id']}, {"$set": result}, upsert=True)
			except Exception:
				pass
		redis_connect.delete('portscan-process-running:{target}'.format(target=target))
		return True
	except Exception:
		logger.error(traceback.format_exc())
		redis_connect.delete('portscan-process-running:{target}'.format(target=target))
		return False

def PortScan(target):
	try:
		results = naabu_scan(target)
		for result in results:
			try:
				result['_id'] = hashlib.md5(str(result['address'] + ':' + str(result['port'])).encode()).hexdigest()
				result['timestamp'] = now()
				mongodb['openports'].insert_one({"_id": result['_id']}, {"$set": result}, upsert=True)
			except Exception:
				logger.error(traceback.format_exc())
				pass
		try:
			portcsv = GetPortFromMongoCSV(target)
			NmapServiceScan(target, portcsv)
		except Exception:
			logger.error(traceback.format_exc())
			pass
		redis_connect.delete('portscan-process-running:{target}'.format(target=target))
		return True
	except Exception:
		logger.error(traceback.format_exc())
		redis_connect.delete('portscan-process-running:{target}'.format(target=target))
		return False

def NucleiScan(input_target):
	try:
		results = nuclei_scan(input_target)
		for result in results:
			result['_id'] = hashlib.md5(str(result).encode()).hexdigest()
			result['timestamp'] = now()
			result['input-value'] = input_target
			result_json = json.dumps(result)
			mongodb['nuclei_results'].update_one({"_id": result['_id']}, {"$set": result}, upsert=True)
		redis_connect.delete('nuclei-process-running:{target}'.format(target=input_target))
		return True
	except Exception:
		redis_connect.delete('nuclei-process-running:{target}'.format(target=input_target))
		return False

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True


########## PROCESSRUNNING SECTIONS HERE [START] ##########

@app.route('/api/v1/processrunning/get', methods=['GET'])
def api_v1_processrunning_get():
	try:
		redis_keys = redis_connect.keys(pattern='*')
		redis_keys = [ redis_key.decode("utf-8") for redis_key in redis_keys ]
		return jsonify({'status': 'success', 'code': 200, 'response': list(redis_keys)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

########## PROCESSRUNNING SECTIONS HERE [END] ##########


########## DOMAINRECON SECTIONS HERE [START] ##########

# API - DOMAINRECON SCAN ENDPOINT
@app.route('/api/v1/domainrecon/scan', methods=['POST'])
def api_v1_domainrecon_scan():
	try:
		get_json = request.get_json(force=True)
		target = get_json['target']
	except Exception:
		return {'status': 'invalid', 'code': 400, 'response': 'there is no [target] provided'}, 400

	#input_target = validatehttp(target)
	#if input_target == False:
	#	return {'status': 'invalid', 'code': 400, 'response': 'could not connect to {}'.format(target)}, 400
	input_target = target

	# Check, is there still the same process running?
	check_task = redis_connect.get('domainrecon-process-running:{target}'.format(target=input_target))
	if check_task:
		return jsonify({'status': 'rejected', 'code': 400, 'response': '{} is still running'.format(input_target)}), 400

	# Run a new scan
	try:
		scan_thread = threading.Thread(target=SubdomainScan, name="SubdomainScan Scanner Worker", args=(input_target,))
		scan_thread.start()
		redis_connect.set('domainrecon-process-running:{target}'.format(target=input_target), 'active')
		return jsonify({'status': 'started', 'code': 200, 'response': 'scanning {}...'.format(input_target)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - DOMAINRECON RESULTS ENDPOINT
@app.route('/api/v1/domainrecon/results', methods=['GET'])
def api_v1_domainrecon_results():
	try:
		data = mongodb['list_domains'].find({}, {'_id': False}).sort('timestamp', DESCENDING)
		return jsonify({'status': 'success', 'code': 200, 'response': list(data)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

########## DOMAINRECON SECTIONS HERE [END] ##########


########## NUCLEI SECTIONS HERE [START] ##########

# API - NUCLEI SCAN ENDPOINT
@app.route('/api/v1/nucleivs/scan', methods=['POST'])
def api_v1_nuclei_scan():
	try:
		get_json = request.get_json(force=True)
		target = get_json['target']
	except Exception:
		return {'status': 'invalid', 'code': 400, 'response': 'there is no [target] provided'}, 400

	input_target = validatehttp(target)
	if input_target == False:
		return {'status': 'invalid', 'code': 400, 'response': 'could not connect to {}'.format(target)}, 400

	# Check, is there still the same process running?
	check_task = redis_connect.get('nuclei-process-running:{target}'.format(target=input_target))
	if check_task:
		return jsonify({'status': 'rejected', 'code': 400, 'response': '{} is still running'.format(input_target)}), 400

	# Run a new scan
	try:
		scan_thread = threading.Thread(target=NucleiScan, name="Nuclei Scanner Worker", args=(input_target,))
		scan_thread.start()
		redis_connect.set('nuclei-process-running:{target}'.format(target=input_target), 'active')
		return jsonify({'status': 'started', 'code': 200, 'response': 'scanning {}...'.format(input_target)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - NUCLEI RESULTS ENDPOINT
@app.route('/api/v1/nucleivs/results', methods=['GET'])
def api_v1_nuclei_results():
	try:
		data = mongodb['nuclei_results'].find({}, {'_id': True, 'input-value': True, 'finding': '$info.name', 'severity': '$info.severity', 'timestamp': True}).sort('timestamp', DESCENDING)
		return jsonify({'status': 'success', 'code': 200, 'response': list(data)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - NUCLEI GET DETAIL BY ID
@app.route('/api/v1/nucleivs/get/<_id>', methods=['GET'])
def api_v1_nuclei_get_by_id(_id):
	try:
		try:
			check = _id
		except Exception:
			return {'status': 'invalid', 'code': 400, 'response': 'there is no [_id] provided'}, 400

		data = mongodb['nuclei_results'].find({'_id': _id})
		return jsonify({'status': 'success', 'code': 200, 'response': list(data)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# DASHBOARD - NUCLEI RESULTS
@app.route('/nucleivs')
def nuclei():
	_header = render_template('_header.html')
	content = render_template('nuclei.html')
	_footer = render_template('_footer.html')
	return _header + content + _footer

# DASHBOARD - NUCLEI DETAIL BY ID
@app.route('/nucleivs/get/<_id>')
def nuclei_get_ip(_id):
	req = requests.get(request.url_root + '/api/v1/nucleivs/get/{_id}'.format(_id=_id))
	_header = render_template('_header.html')
	content = render_template('nuclei-get.html', response=req.json()['response'])
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## NUCLEI SECTIONS HERE [END] ##########


########## PORT-SCAN SECTIONS HERE [START] ##########

# API - PORT-SCAN SCAN ENDPOINT
@app.route('/api/v1/openport/scan', methods=['POST'])
def api_v1_openport_scan():
	try:
		get_json = request.get_json(force=True)
		target = get_json['target']
	except Exception:
		return {'status': 'invalid', 'code': 400, 'response': 'there is no [target] provided'}, 400

	if validateip(target) == False:
		return {'status': 'invalid', 'code': 400, 'response': 'could not connect to {}'.format(target)}, 400

	check_task = redis_connect.get('portscan-process-running:{target}'.format(target=target))
	if check_task:
		return jsonify({'status': 'rejected', 'code': 400, 'response': '{} is still running'.format(target)}), 400
	try:
		scan_thread = threading.Thread(target=PortScan, name="Naabu Port Scanner Worker", args=(target,))
		scan_thread.start()
		redis_connect.set('portscan-process-running:{target}'.format(target=target), 'active')
		return jsonify({'status': 'started', 'code': 200, 'response': 'scanning {}...'.format(target)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - PORT-SCAN RESULTS
@app.route('/api/v1/openport/results', methods=['GET'])
def api_v1_openport_results():
	try:
		data = mongodb['openports'].find({}, {'_id': False, 'address': True, 'port': True, 'protocol': True, 'service': '$service.@name', 'timestamp': True}).sort('timestamp', DESCENDING)
		return jsonify({'status': 'success', 'code': 200, 'response': list(data)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - PORT-SCAN GET DETAIL BY IP
@app.route('/api/v1/openport/get/<ip>', methods=['GET'])
def api_v1_openport_get_by_id(ip):
	try:
		try:
			check = ip
		except Exception:
			return {'status': 'invalid', 'code': 400, 'response': 'there is no [_id] provided'}, 400

		data = mongodb['openports'].find({'address': ip}, {'_id': False, 'address': False})
		return jsonify({'status': 'success', 'code': 200, 'response': {'host': ip, 'ports': list(data)}}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# DASHBOARD - PORT-SCAN RESULTS
@app.route('/openport')
def openport():
	_header = render_template('_header.html')
	content = render_template('openport.html')
	_footer = render_template('_footer.html')
	return _header + content + _footer

# DASHBOARD - PORT-SCAN GET DETAIL BY IP
@app.route('/openport/get/<ip>')
def openport_get_ip(ip):
	req = requests.get(request.url_root + '/api/v1/openport/get/{ip}'.format(ip=ip))
	_header = render_template('_header.html')
	content = render_template('openport-get.html', response=req.json()['response'])
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## NMAP SECTIONS HERE [END] ##########


########## SHODAN SMAP HERE [START] ##########

# API - SHODAN SMAP
@app.route('/api/v1/shodansmap/get/<target>', methods=['GET'])
def api_v1_shodansmap_get_by_target(target):
	try:
		result = shodansmap_scan(target)
		return jsonify({'status': 'success', 'code': 200, 'response': result}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# DASHBOARD - SHODAN SMAP
@app.route('/shodansmap')
def shodansmap():
	_header = render_template('_header.html')
	content = render_template('shodansmap.html')
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## SHODAN SMAP HERE [END] ##########


########## IPTOASN SECTIONS [START] ##########

@app.route('/api/v1/asnumber/get/<ip>', methods=['GET'])
def api_v1_asnumber_get_by_ip(ip):
	try:
		IPTOASN_HOST = os.getenv('IPTOASN_HOST', 'iptoasn-webservice')
		req = requests.get('http://{IPTOASN_HOST}/api/v1/asnumber/get/{IP}'.format(IPTOASN_HOST=IPTOASN_HOST, IP=ip))
		return jsonify({'status': 'success', 'code': 200, 'response': req.json()}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

########## IPTOASN SECTIONS [END] ##########


########## DASHBOARD INDEX [START] ##########

@app.route('/')
def dashboard_index():
	_header = render_template('_header.html')
	content = '<div class="p-5"><h1 class="fw-bolder text-success">Welcome to the Jungle!</h1><h1 class="fw-bolder text-secondary">We got fun and games!</h1></div>'
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## DASHBOARD INDEX [ENDS] ##########

if __name__ == '__main__':
	app.run(host=LISTEN_ADDR, port=LISTEN_PORT, debug=APP_DEBUG)