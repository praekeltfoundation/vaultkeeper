import responses

from ..vaultkeeper import Vaultkeeper
from ..vaultkeeper import ConfigParser
from vaultkeeper import secret
from fake_vault import FakeVault
from fake_gatekeeper import FakeGatekeeper


def configs():
    data = {
        'gatekeeper_addr': 'https://test-gatekeeper-instance.net',
        'vault_addr': 'https://test-vault-instance.net',
        'entry_script': '',
        'working_directory': '',
        'log_path': '../../logs/testlog.log',
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
        responses.add_callback(responses.POST,
                               self.fake_gatekeeper_url + '/token',
                               callback=self.fake_gatekeeper.get_token,
                               content_type='application/json')

        wrapped_token = self.vaultkeeper.get_wrapped_token()
        assert wrapped_token == '10000000-1000-1000-1000-100000000000'

    @responses.activate
    def test_unwrap_token(self):
        responses.add_callback(responses.GET,
                               self.fake_vault_url + '/v1/auth/token/lookup-self',
                               callback=self.fake_vault.lookup_self,
                               content_type='application/json')
        responses.add_callback(responses.POST,
                               self.fake_vault_url + '/v1/sys/wrapping/unwrap',
                               callback=self.fake_vault.unwrap_token,
                               content_type='application/json')

        unwrapped_token = self.vaultkeeper.unwrap_token(
            '10000000-1000-1000-1000-100000000000')
        assert unwrapped_token == '00000000-0000-0000-0000-000000000001'

    @responses.activate
    def test_authenticated(self):
        responses.add_callback(responses.POST,
                               self.fake_vault_url + '/v1/auth/token/lookup',
                               callback=self.fake_vault.lookup_self,
                               content_type='application/json')
        pass

    @responses.activate
    def test_get_cred(self):
        self.vaultkeeper.vault_client.token = '00000000-0000-0000-0000-000000000001'
        responses.add_callback(responses.GET,
                               self.fake_vault_url + '/v1/auth/token/lookup-self',
                               callback=self.fake_vault.lookup_self,
                               content_type='application/json')
        responses.add_callback(responses.GET,
                               self.fake_vault_url
                               + '/v1/database/creds/postgresql_myschema_readonly',
                               callback=self.fake_vault.get_db_creds,
                               content_type='application/json')
        self.vaultkeeper.get_creds()
        assert (secret.printable_secrets(self.vaultkeeper.secrets) == {
                'creds1': {
                    'endpoint': 'https://test-postgres-instance.net',
                    'vault_path': 'database/creds/postgresql_myschema_readonly',
                    'policy': 'read',
                    'renewable': True,
                    'lease_id': 'database/creds/postgresql_myschema_readonly/lease-id1',
                    'lease_duration': 100,
                    'username': 'testuser1',
                    'password': 'testpass1'
                }
        })

    @responses.activate
    def test_renew_token(self):
        self.vaultkeeper.vault_client.token = '00000000-0000-0000-0000-000000000001'
        responses.add_callback(responses.GET,
                               self.fake_vault_url + '/v1/auth/token/lookup-self',
                               callback=self.fake_vault.lookup_self,
                               content_type='application/json')

        responses.add_callback(responses.POST,
                               self.fake_vault_url + '/v1/auth/token/renew',
                               callback=self.fake_vault.renew_lease,
                               content_type='application/json')

    @responses.activate
    def test_renew_lease(self):
        self.vaultkeeper.vault_client.token = '00000000-0000-0000-0000-000000000001'
        responses.add_callback(responses.GET,
                               self.fake_vault_url + '/v1/auth/token/lookup-self',
                               callback=self.fake_vault.lookup_self,
                               content_type='application/json')

        responses.add_callback(responses.PUT,
                               self.fake_vault_url + '/v1/sys/leases/renew',
                               callback=self.fake_vault.renew_lease,
                               content_type='application/json')

        renew = self.vaultkeeper.secrets['creds1']
        renew.add_secret({
            'lease_id': 'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 300,
            'renewable': True,
            'data': {
                'username': 'testuser1',
                'password': 'testpass1'
            }
        })
        self.vaultkeeper.renew_lease(renew)
        assert renew.lease_duration == 300
