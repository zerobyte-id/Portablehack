#!/usr/bin/env python3

import warnings
from modules.validatehttp import *
from modules.nuclei_scanner import *
from modules.nmap_scanner import *
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

def NmapScan(target):
	try:
		results = nmap_portscan(target)
		for result in results:
			try:
				result['timestamp'] = now()
				mongodb['nmap_openports'].update_one({"address": result['address'], "port": result['port']}, {"$set": result}, upsert=True)
			except Exception:
				pass
		redis_connect.hdel('nmapprocess', target, 1)
		return True
	except Exception:
		redis_connect.hdel('nmapprocess', target, 1)
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
		redis_connect.hdel('nucleiprocess', input_target, 1)
		return True
	except Exception:
		redis_connect.hdel('nucleiprocess', input_target, 1)
		return False



app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True



########## NUCLEI SECTIONS HERE [START] ##########

# API - NUCLEI SCAN ENDPOINT
@app.route('/api/v1/nuclei/scan', methods=['POST'])
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
	check_task = redis_connect.hget('nucleiprocess', input_target)
	if check_task:
		return jsonify({'status': 'rejected', 'code': 400, 'response': '{} is still running'.format(input_target)}), 400

	# Run a new scan
	try:
		scan_thread = threading.Thread(target=NucleiScan, name="Nuclei Scanner Worker", args=(input_target,))
		scan_thread.start()
		redis_connect.hset('nucleiprocess', input_target, 1)
		return jsonify({'status': 'started', 'code': 200, 'response': 'scanning {}...'.format(input_target)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - NUCLEI RESULTS ENDPOINT
@app.route('/api/v1/nuclei/results', methods=['GET'])
def api_v1_nuclei_results():
	try:
		data = mongodb['nuclei_results'].find({}, {'_id': True, 'input-value': True, 'finding': '$info.name', 'severity': '$info.severity', 'timestamp': True}).sort('timestamp', DESCENDING)
		return jsonify({'status': 'success', 'code': 200, 'response': list(data)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - NUCLEI GET DETAIL BY ID
@app.route('/api/v1/nuclei/get/<_id>', methods=['GET'])
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
@app.route('/nuclei')
def nuclei():
	_header = render_template('_header.html')
	content = render_template('nuclei.html')
	_footer = render_template('_footer.html')
	return _header + content + _footer

# DASHBOARD - NUCLEI DETAIL BY ID
@app.route('/nuclei/get/<_id>')
def nuclei_get_ip(_id):
	req = requests.get(request.url_root + '/api/v1/nuclei/get/{_id}'.format(_id=_id))
	_header = render_template('_header.html')
	content = render_template('nuclei-get.html', response=req.json()['response'])
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## NUCLEI SECTIONS HERE [END] ##########



########## NMAP SECTIONS HERE [START] ##########

# API - NMAP SCAN ENDPOINT
@app.route('/api/v1/nmap/scan', methods=['POST'])
def api_v1_nmap_scan():
	try:
		get_json = request.get_json(force=True)
		target = get_json['target']
	except Exception:
		return {'status': 'invalid', 'code': 400, 'response': 'there is no [target] provided'}, 400

	if validateip(target) == False:
		return {'status': 'invalid', 'code': 400, 'response': 'could not connect to {}'.format(target)}, 400

	check_task = redis_connect.hget('nmapprocess', target)
	if check_task:
		return jsonify({'status': 'rejected', 'code': 400, 'response': '{} is still running'.format(target)}), 400
	try:
		scan_thread = threading.Thread(target=NmapScan, name="NMAP Port Scanner Worker", args=(target,))
		scan_thread.start()
		redis_connect.hset('nmapprocess', target, 1)
		return jsonify({'status': 'started', 'code': 200, 'response': 'scanning {}...'.format(target)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - NMAP RESULTS
@app.route('/api/v1/nmap/results', methods=['GET'])
def api_v1_nmap_results():
	try:
		data = mongodb['nmap_openports'].find({}, {'_id': False, 'address': True, 'port': True, 'protocol': True, 'service': '$service.@name', 'timestamp': True}).sort('timestamp', DESCENDING)
		return jsonify({'status': 'success', 'code': 200, 'response': list(data)}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# API - NMAP GET DETAIL BY IP
@app.route('/api/v1/nmap/get/<ip>', methods=['GET'])
def api_v1_nmap_get_by_id(ip):
	try:
		try:
			check = ip
		except Exception:
			return {'status': 'invalid', 'code': 400, 'response': 'there is no [_id] provided'}, 400

		data = mongodb['nmap_openports'].find({'address': ip}, {'_id': False, 'address': False})
		return jsonify({'status': 'success', 'code': 200, 'response': {'host': ip, 'ports': list(data)}}), 200
	except Exception:
		logger.error(traceback.format_exc())
		return {'status': 'error', 'code': 500, 'response': 'unknown error please contact your administrator'}, 500

# DASBOARD - NMAP RESULTS
@app.route('/nmap')
def nmap():
	_header = render_template('_header.html')
	content = render_template('nmap.html')
	_footer = render_template('_footer.html')
	return _header + content + _footer

# DASBOARD - NMAP GET DETAIL BY IP
@app.route('/nmap/get/<ip>')
def nmap_get_ip(ip):
	req = requests.get(request.url_root + '/api/v1/nmap/get/{ip}'.format(ip=ip))
	_header = render_template('_header.html')
	content = render_template('nmap-get.html', response=req.json()['response'])
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## NMAP SECTIONS HERE [END] ##########



########## DASHBOARD INDEX [START] ##########

@app.route('/')
def dashboard_index():
	_header = render_template('_header.html')
	content = '<div class="p-3"><h1>Welcome to the Jungle!</h1></div>'
	_footer = render_template('_footer.html')
	return _header + content + _footer

########## DASHBOARD INDEX [ENDS] ##########

if __name__ == '__main__':
	app.run(host=LISTEN_ADDR, port=LISTEN_PORT, debug=APP_DEBUG)