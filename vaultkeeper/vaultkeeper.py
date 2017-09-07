import logging
import json
import os
import sys
import shlex
import subprocess32 as subprocess
from subprocess32 import TimeoutExpired
from configparser import ConfigParser
import secret
import hvac
import requests


def get_mesos_taskid(env=os.environ):
    taskid = env['MESOS_TASK_ID']
    if taskid is None:
        raise KeyError('Could not retrieve Mesos task ID.')
    return taskid


def get_vaultkeeper_cfg(env=os.environ):
    path = env['VAULTKEEPER_CONFIG']
    if path is None:
        raise KeyError('Could not retrieve Vaultkeeper config path.')
    return path


def get_secrets_cfg(env=os.environ):
    path = env['SECRETS_CONFIG']
    if path is None:
        raise KeyError('Could not retrieve Secrets configuration path.')
    return path


def get_marathon_appname(env=os.environ):
    appname = env['MARATHON_APP_ID']
    if appname is None:
        raise KeyError('Could not retrieve Marathon app name.')
    return appname


def get_vault_addr(env=os.environ):
    vault_addr = env['VAULT_ADDR']
    if vault_addr is None:
        raise KeyError('Could not retrieve Vault address.')
    return vault_addr


def get_gatekeeper_addr(env=os.environ):
    gatekeeper_addr = env['GATEKEEPER_ADDR']
    if gatekeeper_addr is None:
        raise KeyError('Could not retrieve Gatekeeper address.')
    return gatekeeper_addr


class Vaultkeeper(object):
    logger = logging.getLogger(__name__)

    def __init__(self,
                 configs=None, secrets=None,
                 taskid=None, appname=None,
                 vault_addr=None,
                 gatekeeper_addr=None):
        """
        Create the Vaultkeeper service.

        :param configs: A ConfigParser object.
        :param secrets: A nested dictionary of Secret objects.
        :param taskid: The Mesos task ID for this process' context.
        :param appname: The Marathon app name for this process' context.
        :param vault_addr: The address for the Vault server.
        :param gatekeeper_addr: The address for the Gatekeeper server.
        """
        self.configs = configs
        self.secrets = secrets
        self.taskid = taskid
        self.appname = appname
        self.vault_addr = vault_addr
        self.gatekeeper_addr = gatekeeper_addr
        self.app = None

    def setup(self):
        self.vault_client = hvac.Client(url=self.vault_addr)

    def get_wrapped_token(self):
        payload = {'task_id': self.taskid}
        r = requests.post(self.gatekeeper_addr + '/token',
                          json=payload)
        response = r.json()
        if response['ok']:
            self.wrapped_token = response['token']
            return self.wrapped_token
        raise RuntimeError('The service encountered an error '
                           + 'retrieving its wrapped token '
                           + 'from Gatekeeper: '
                           + response.text)

    def unwrap_token(self, wrapped_token):
        self.vault_secret = secret.UnwrappedToken('vault_token', 'token')
        response = self.vault_client.unwrap(wrapped_token)
        self.vault_secret.add_secret(response)
        self.vault_client.token = self.vault_secret.token_value
        if not self.vault_client.is_authenticated():
            raise RuntimeError('The service could not authenticate'
                               + 'to Vault with the unwrapped token.')
        return self.vault_client.token

    def write_credentials(self):
        data = secret.printable_secrets(self.secrets)
        with open(self.configs.credential_path, 'w') as outfile:
            json.dump(data, outfile)

    def get_cred(self, vault_path):
        if not self.vault_client.is_authenticated():
            raise RuntimeError('The service could not authenticate '
                               + 'to Vault to retrieve credentials.')
        return self.vault_client.read(vault_path)

    def get_creds(self):
        for cred in self.secrets.itervalues():
            response = self.get_cred(cred.vault_path)
            cred.add_secret(response)

    def renew_token(self, ttl):
        result = self.vault_client.renew_token(increment=ttl)
        self.vault_secret.update_ttl(ttl)
        return result

    def renew_lease(self, s):
        assert self.vault_client.is_authenticated()
        result = self.vault_client.renew_secret(s.lease_id,
                                                s.lease_duration)
        s.update_lease(s.lease_id, s.lease_duration)
        return result

    def renew_all(self):
        for entry in self.secrets.itervalues():
            if entry.renewable:
                self.renew_lease(entry)

    def cleanup(self):
        self.vault_client.revoke_self_token()

    def start_subprocess(self):
        self.get_wrapped_token()
        self.unwrap_token(self.wrapped_token)
        self.logger.info('Written credentials to '
                         + self.configs.credential_path)
        self.get_creds()
        self.write_credentials()
        args = shlex.split(self.configs.entry_cmd.encode(
            'utf-8', errors='ignore'))
        self.app = subprocess.Popen(args,
                                    shell=False
                                    )

    def watch_and_renew(self):
        while True:
            try:
                self.app.wait(timeout=self.configs.refresh_interval)
            except TimeoutExpired:
                self.logger.info('Renewing leases...')
                self.renew_token(self.vault_secret.lease_duration)
                self.renew_all()
            else:
                self.cleanup()
                return self.app.returncode

    def run(self):
        self.start_subprocess()
        return self.watch_and_renew()


def main():
    config = get_vaultkeeper_cfg()
    secrets = get_secrets_cfg()
    taskid = get_mesos_taskid()
    appname = get_marathon_appname()
    vault_addr = get_vault_addr()
    gatekeeper_addr = get_gatekeeper_addr()

    configs = ConfigParser(config_path=config)
    configs.load_configs()

    required_secrets = secret.parse_secret_file(secrets)

    vaultkeeper = Vaultkeeper(configs=configs,
                              secrets=required_secrets,
                              taskid=taskid,
                              appname=appname,
                              vault_addr=vault_addr,
                              gatekeeper_addr=gatekeeper_addr
                              )
    vaultkeeper.setup()
    returncode = vaultkeeper.run()
    sys.exit(returncode)


if __name__ == '__main__':
    main()
