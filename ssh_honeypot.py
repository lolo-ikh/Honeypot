# Libraries
import logging
from logging.handlers import RotatingFileHandler
# Constants
logging_format = logging.Formatter('%(message)s')

# Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5) # audits.log will store the info f the ip password username.
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5) # cmd_audits.log will store the info of the commands executed by the attacker.
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)



# Emulated Shell

# SSH Server + Sockets

# Provision SSH-based Honeypot