import responses
import os
import signal
import threading

from ..vaultkeeper import Vaultkeeper
from ..vaultkeeper import ConfigParser
from vaultkeeper import secret
from fake_vault import FakeVault
from fake_gatekeeper import FakeGatekeeper


def configs():
    data = {
        'gatekeeper_addr': 'https://test-gatekeeper-instance.net',
        'vault_addr': 'https://test-vault-instance.net',
        'entry_cmd': '',
        'credential_path': '',
        'refresh_interval': 30,
        'renewal_grace': 15,
    }

    cfgs = ConfigParser()
    cfgs.load_data(data)
    return cfgs


def secrets():
    data = [{
        'id': 'creds1',
        'backend': 'database',
        'endpoint': 'https://test-postgres-instance.net',
        'vault_path': 'database/creds/postgresql_myschema_readonly',
        'schema': 'myschema',
        'policy': 'read'
    }]
    return secret.parse_secret_data(data)


def vault_token():
    vault_secret = secret.Token('vault-token', 'token')
    vault_secret.add_secret({
        'lease_id': 'auth/token/create/lease-id1',
        'lease_duration': 30,
        'renewable': True,
        'vault_path': '/vault/token/path',
        'data': {
            'token': '00000000-0000-0000-0000-000000000001',
        }
    }
    )
    return vault_secret


class TestVaultkeeper(object):
    def setup(self):
        self.configs = configs()
        self.secrets = secrets()
        self.vaultkeeper = Vaultkeeper(
            configs=self.configs,
            secrets=self.secrets,
            taskid='purple-rain-486-ab24134bed3423f124937',
            appname='purple-rain-486',
            vault_addr='https://test-vault-instance.net',
            gatekeeper_addr='https://test-gatekeeper-instance.net'
        )
        self.vaultkeeper.setup()
        self.fake_vault = FakeVault()
        self.fake_vault.setup()
        self.fake_gatekeeper = FakeGatekeeper()
        self.fake_gatekeeper.setup()
        self.fake_vault_url = 'https://test-vault-instance.net'
        self.fake_gatekeeper_url = 'https://test-gatekeeper-instance.net'

    @responses.activate
    def test_get_wrapped_token(self):
        self.fake_gatekeeper.add_handlers(responses, self.fake_gatekeeper_url)
        wrapped_token = self.vaultkeeper.get_wrapped_token()
        assert wrapped_token == '10000000-1000-1000-1000-100000000000'

    @responses.activate
    def test_unwrap_token(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        unwrapped_token = self.vaultkeeper.unwrap_token(
            '10000000-1000-1000-1000-100000000000')
        assert unwrapped_token == '00000000-0000-0000-0000-000000000001'

    @responses.activate
    def test_authenticated(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        assert self.vaultkeeper.vault_client.is_authenticated()

    @responses.activate
    def test_get_cred(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.vaultkeeper.get_creds()
        assert (secret.printable_secrets(self.vaultkeeper.secrets) == [{
            'id': 'creds1',
            'backend': 'database',
            'endpoint': 'https://test-postgres-instance.net',
            'vault_path':
                'database/creds/postgresql_myschema_readonly',
            'policy': 'read',
            'renewable': True,
            'lease_id':
                'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 100,
            'username': 'testuser1',
            'password': 'testpass1'

        }])

    @responses.activate
    def test_renew_token(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.vaultkeeper.vault_secret = vault_token()
        self.vaultkeeper.renew_token(30)
        assert self.vaultkeeper.vault_secret.lease_duration == 30

    @responses.activate
    def test_renew_lease(self):
        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.fake_vault.add_handlers(responses, self.fake_vault_url)

        renew = self.vaultkeeper.secrets['creds1']
        renew.add_secret({
            'lease_id':
                'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 300,
            'renewable': True,
            'data': {
                'username': 'testuser1',
                'password': 'testpass1'
            }
        })
        self.vaultkeeper.renew_lease(renew)
        assert renew.lease_duration == 300

    @responses.activate
    def test_run_normal_success(self, tmpdir):
        self.fake_gatekeeper.add_handlers(responses, self.fake_gatekeeper_url)
        self.fake_vault.add_handlers(responses, self.fake_vault_url)

        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.vaultkeeper.vault_secret = vault_token()
        self.vaultkeeper.configs.credential_path = (
            tmpdir.join('./creds.txt').strpath)

        self.vaultkeeper.configs.entry_cmd = 'python ./test/normal_success.py'
        self.vaultkeeper.configs.refresh_interval = 0.1
        status_code = self.vaultkeeper.run()
        assert status_code == 0

    @responses.activate
    def test_run_normal_failure(self, tmpdir):
        self.fake_gatekeeper.add_handlers(responses, self.fake_gatekeeper_url)
        self.fake_vault.add_handlers(responses, self.fake_vault_url)

        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.vaultkeeper.vault_secret = vault_token()
        self.vaultkeeper.configs.credential_path = (
            tmpdir.join('./creds.txt').strpath)

        self.vaultkeeper.configs.entry_cmd = 'python ./test/normal_failure.py'
        self.vaultkeeper.configs.refresh_interval = 0.1
        status_code = self.vaultkeeper.run()
        assert status_code == 3

    @responses.activate
    def test_run_abnormal_failure(self, tmpdir):
        """
        Vaultkeeper should clean up properly even if the subprocessed
        application terminates in a way that is not implicated in its
        natural lifecycle, ie. via SIGKILL.
        """
        self.fake_gatekeeper.add_handlers(responses, self.fake_gatekeeper_url)
        self.fake_vault.add_handlers(responses, self.fake_vault_url)

        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.vaultkeeper.vault_secret = vault_token()
        self.vaultkeeper.configs.credential_path = (
            tmpdir.join('./creds.txt').strpath)

        self.vaultkeeper.configs.entry_cmd = (
            'python ./test/abnormal_failure.py')
        self.vaultkeeper.configs.refresh_interval = 0.1
        self.vaultkeeper.start_subprocess()
        t = threading.Thread(target=self.vaultkeeper.watch_and_renew)
        t.start()
        spid = self.vaultkeeper.app.pid
        os.kill(spid, signal.SIGKILL)
        t.join()
        assert (self.vaultkeeper.vault_client.is_authenticated()
                is False)
