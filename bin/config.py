import os

# API parameters
API_URL = "https://censys.io/api/v1/bulk/certificates"
API_ID = os.getenv("API_ID", None)
API_SECRET = os.getenv("API_SECRET", None)
API_TIMEOUT = 60

# Configuration parameters
# Most users need not modify these
DEFAULT_SPLUNK_HOME = "/opt/splunk/"
SPLUNK_LIB_PATH = "etc/apps/cert-enricher/lib"

# Logging parameters
LOGGING_LEVEL = "ERROR"
LOGFILE_PATH = "../var/log/enrich.log"

# Performance parameters
MAX_WORKER_THREADS = 8
