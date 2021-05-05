"""
Project-wide default settings

These are in their own file so they can be imported by setup.py before we have
any of our dependencies installed.
"""

UAC_ETC_PATH = "/etc/ubuntu-advantage/"
DEFAULT_DATA_DIR = "/var/lib/ubuntu-advantage"
DEFAULT_MACHINE_TOKEN_PATH = DEFAULT_DATA_DIR + "/private/machine-token.json"
DEFAULT_CONFIG_FILE = UAC_ETC_PATH + "uaclient.conf"
DEFAULT_HELP_FILE = UAC_ETC_PATH + "help_data.yaml"
DEFAULT_UPGRADE_CONTRACT_FLAG_FILE = UAC_ETC_PATH + "request-update-contract"
BASE_CONTRACT_URL = "https://contracts.canonical.com"
BASE_SECURITY_URL = "https://ubuntu.com/security"
BASE_UA_URL = "https://ubuntu.com/advantage"
EOL_UA_URL_TMPL = "https://ubuntu.com/{hyphenatedrelease}"
BASE_ESM_URL = "https://ubuntu.com/esm"
PRINT_WRAP_WIDTH = 80
CONTRACT_EXPIRY_GRACE_PERIOD_DAYS = 14
CONTRACT_EXPIRY_PENDING_DAYS = 20

CONFIG_DEFAULTS = {
    "contract_url": BASE_CONTRACT_URL,
    "security_url": BASE_SECURITY_URL,
    "data_dir": DEFAULT_DATA_DIR,
    "log_level": "INFO",
    "log_file": "/var/log/ubuntu-advantage.log",
}
