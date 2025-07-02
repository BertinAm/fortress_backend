# utils/logger.py

import logging

logger = logging.getLogger('fortress_monitor')

def setup_logger():
    handler = logging.FileHandler('fortress.log')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

def log_info(message):
    logger.info(message)

def log_error(message):
    logger.error(message)
