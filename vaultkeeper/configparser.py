import json


class ConfigParser(object):
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.vault_addr = None
        self.gatekeeper_addr = None
        self.entry_script = None
        self.working_dir = None
        self.log_path = None
        self.credential_path = None
        self.lease_path = None
        self.token_refresh = None
        self.refresh_interval = None
        self.renewal_grace = None

    def load_data(self, data):
        self.vault_addr = data['vault_addr']
        self.gatekeeper_addr = data['gatekeeper_addr']
        self.entry_script = data['entry_script']
        self.working_dir = data['working_directory']
        self.log_path = data['log_path']
        self.credential_path = data['credential_path']
        self.lease_path = data['lease_path']
        self.token_refresh = data['token_refresh']
        self.refresh_interval = data['refresh_interval']
        self.renewal_grace = data['renewal_grace']

    def load_configs(self):
        with open(self.config_path) as agent_config:
            data = json.load(agent_config)
        self.load_data(data)
