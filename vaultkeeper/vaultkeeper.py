import logging
import time
import json
import daemon
import signal
import os
import sys
import subprocess
from configparser import ConfigParser
import secret
import hvac
import requests


def get_mesos_taskid(env=os.environ):
    taskid = env['MESOS_TASKID']
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
    appname = env['MARATHON_APPNAME']
    if appname is None:
        raise KeyError('Could not retrieve Marathon app name.')
    return appname


class Vaultkeeper(object):
    def __init__(self,
                 configs, secrets,
                 taskid, appname):
        """
        Create the Vaultkeeper service.

        :param configs: A ConfigParser object.
        :param secrets: A nested dictionary of Secret objects.
        :param taskid: The Mesos task ID for this process' context.
        :param appname: The Marathon app name for this process' context.
        """
        self.configs = configs
        self.secrets = secrets
        self.taskid = taskid
        self.appname = appname

    def setup(self):
        self.vault_client = hvac.Client(url=self.configs.vault_addr)
        self.logger = logging.getLogger('DaemonLog')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.FileHandler(self.configs.log_path)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.context = daemon.DaemonContext(
            files_preserve=[
                handler.stream,
            ],
            working_directory=self.configs.working_dir,
            umask=117,
            stdout=sys.stdout,
            stderr=sys.stderr,
            detach_process=False,
            signal_map={
                signal.SIGTERM: None,
                signal.SIGHUP: None,
                signal.SIGUSR1: None,
            },
        )

    def get_wrapped_token(self):
        payload = {'task_id': self.taskid}
        r = requests.post(self.configs.gatekeeper_addr + '/token',
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
        self.vault_secret = secret.Token('vault_token', 'token')
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
            raise RuntimeError('The service could not authenticate'
                               + 'to Vault to retrieve credentials.')
        return self.vault_client.read(vault_path)

    def get_creds(self):
        for cred in self.secrets.itervalues():
            response = self.get_cred(cred.vault_path)
            cred.add_secret(response)

    def renew_token(self):
        self.vault_client.renew_secret(self.vault_secret.lease_id,
                                       self.configs.refresh_interval)
        self.vault_secret.update_lease(self.vault_secret.lease_id,
                                       self.configs.refresh_interval)
        return self.vault_secret

    def renew_lease(self, s):
        assert self.vault_client.is_authenticated()
        self.vault_client.renew_secret(s.lease_id,
                                       s.lease_duration)
        s.update_lease(s.lease_id, s.lease_duration)
        return s

    def renew_all(self):
        for entry in self.secrets.itervalues():
            for s in entry.itervalues():
                if s.renewable:
                    self.renew_lease(s)

    def run(self):
        with self.context:
            logger = logging.getLogger('DaemonLog')
            self.get_wrapped_token()
            logger.info('Written credentials to ' + self.configs.credential_path)
            self.get_creds()
            self.write_credentials()
            django = subprocess.Popen(['sh', self.configs.entry_script],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT)
            while django.poll() is None:
                self.renew_token()
                self.renew_all()
                time.sleep(self.configs.refresh_interval)


def main():
    config = get_vaultkeeper_cfg()
    secrets = get_secrets_cfg()
    taskid = get_mesos_taskid()
    appname = get_marathon_appname()

    configs = ConfigParser(config_path=config)
    configs.load_configs()

    required_secrets = secret.parse_secret_file(secrets)

    vaultkeeper = Vaultkeeper(configs, required_secrets, taskid, appname)
    vaultkeeper.setup()
    vaultkeeper.run()
    exit(0)


if __name__ == '__main__':
    main()
