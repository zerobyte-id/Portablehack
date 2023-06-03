#!/usr/bin/env python3

import os
import logging
import sys
import traceback

LOGGING_LEVEL = os.getenv('LOGGING_LEVEL', 'INFO')

try:
	logger = logging.getLogger()
	logger.setLevel(LOGGING_LEVEL)
	formatter = logging.Formatter('[%(asctime)s] %(levelname)s: {%(filename)s:%(lineno)d} - %(message)s')
	handler = logging.StreamHandler(sys.stdout)
	handler.setFormatter(formatter)
	logger.addHandler(handler)
except Exception:
	print('ERROR! logger was not working', traceback.format_exc())
	exit()