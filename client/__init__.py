'''
Created on Feb 15, 2021
@author: ft
'''
import logging
from colorlog import ColoredFormatter
logger = logging.getLogger()
handler = logging.StreamHandler()

# Here is where the log formatting change needs to go
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(log_color)s%(asctime)s %(levelname)-8s%(reset)s %(log_color)s%(message)s%(reset)s' #, '%m/%d/%Y %I:%M:%S'
logging.root.setLevel(LOG_LEVEL)
formatter = ColoredFormatter(LOG_FORMAT)
stream = logging.StreamHandler()
stream.setLevel(LOG_LEVEL)
stream.setFormatter(formatter)
logging.root.addHandler(stream)
# Reduce the log screaming . . .
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('conjur')
logging.getLogger('requests_kerberos').setLevel(logging.WARNING)

