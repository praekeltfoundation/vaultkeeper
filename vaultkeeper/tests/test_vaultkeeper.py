import responses
import ctypes
import os
import signal

from ..vaultkeeper import Vaultkeeper
from ..vaultkeeper import ConfigParser
from vaultkeeper import secret
from fake_vault import FakeVault
from fake_gatekeeper import FakeGatekeeper
from multiprocessing import Process


def terminate_thread(thread):
    """Terminates a python thread from another thread.

    :param thread: a threading.Thread instance
    """
    if not thread.isAlive():
        return

    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def configs():
    data = {
        'gatekeeper_addr': 'https://test-gatekeeper-instance.net',
        'vault_addr': 'https://test-vault-instance.net',
        'entry_cmd': '',
        'working_directory': '',
        'credential_path': '',
        'lease_path': '',
        'token_refresh': 300,
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
            self.configs,
            self.secrets,
            'purple-rain-486-ab24134bed3423f124937',
            'purple-rain-486'
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
        assert (secret.printable_secrets(self.vaultkeeper.secrets) == {
            'id': 'creds1',
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

        })

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
    def test_run_natural_success(self, tmpdir):
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
    def test_run_natural_failure(self, tmpdir):
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
    def test_run_unnatural_failure(self, tmpdir):
        self.fake_gatekeeper.add_handlers(responses, self.fake_gatekeeper_url)
        self.fake_vault.add_handlers(responses, self.fake_vault_url)

        self.vaultkeeper.vault_client.token = (
            '00000000-0000-0000-0000-000000000001')
        self.vaultkeeper.vault_secret = vault_token()
        self.vaultkeeper.configs.credential_path = (
            tmpdir.join('./creds.txt').strpath)

        self.vaultkeeper.configs.entry_cmd = 'python ./test/normal_failure.py'
        self.vaultkeeper.configs.refresh_interval = 0.1
        p = Process(target=self.vaultkeeper.run())
        p.start()
        pid = p.pid
        assert pid is not None
        os.kill(pid, signal.SIGKILL)
        p.join()
        assert (self.vaultkeeper.vault_client.is_authenticated()
                is False)
