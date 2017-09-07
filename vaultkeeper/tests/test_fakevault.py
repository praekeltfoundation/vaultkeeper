import requests
import responses

from fake_vault import FakeVault


class TestFakeVault(object):
    def setup(self):
        self.fake_vault = FakeVault()
        self.fake_vault.setup()
        self.fake_vault_url = 'https://test-vault-instance.net'

    @responses.activate
    def test_get_wrapped_token(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000000',
            'X-Vault-Wrap-TTL': '20s'
        }
        payload = {
            'policies': ['default', 'django-consumer'],
            'ttl': '1h',
            'renewable': True
        }

        resp = requests.post(self.fake_vault_url + '/v1/auth/token/create',
                             headers=headers, json=payload)

        assert resp.json() == {
            'request_id': '',
            'lease_id': '',
            'renewable': False,
            'lease_duration': 0,
            'data': None,
            'wrap_info': {
                'token': '10000000-1000-1000-1000-100000000000',
                'ttl': 200,
                'creation_time': '2016-10-13T15:32:05.6789703Z'
            },
            'warnings': None,
            'auth': None
        }

    @responses.activate
    def test_unwrap_client_token(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '10000000-1000-1000-1000-100000000000'
        }

        resp = requests.post(self.fake_vault_url + '/v1/sys/wrapping/unwrap',
                             headers=headers)
        assert resp.json() == {
                'request_id': '',
                'lease_id': '',
                'lease_duration': 0,
                'renewable': False,
                'auth': {
                    'client_token': '00000000-0000-0000-0000-000000000001',
                    'accessor': '',
                    'policies': ['default', 'gatekeeper'],
                    'metadata': None,
                    'lease_duration': 2764800,
                    'renewable': True
                },
                'warnings': None
            }

    @responses.activate
    def test_authenticated(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }

        resp = requests.get(self.fake_vault_url + '/v1/auth/token/lookup-self',
                            headers=headers)
        assert resp.json() == {
            'data': {
                'policies': ['default', 'django-consumer']
            }
        }

    @responses.activate
    def test_get_psql_creds(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }

        resp = requests.get(self.fake_vault_url
                            + '/v1/database/creds/'
                              'postgresql_myschema_readonly',
                            headers=headers)

        assert resp.json() == {
            'lease_id':
                'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 100,
            'renewable': True,
            'data': {
                'username': 'testuser1',
                'password': 'testpass1'
            }
        }

    @responses.activate
    def test_renew_lease(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }

        payload = {
            'lease_id':
                'database/creds/postgresql_myschema_readonly/lease-id1',
            'increment': 30
        }
        resp = requests.put(self.fake_vault_url + '/v1/sys/leases/renew',
                            headers=headers,
                            json=payload)

        assert resp.json() == {
            'lease_id':
                'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 30,
            'renewable': True
        }

    @responses.activate
    def test_renew_expired_lease(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        self.fake_vault.expire_lease()
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }

        payload = {
            'lease_id':
                'database/creds/postgresql/'
                'postgresql_myschema_readonly/lease-id1',
            'increment': 30
        }
        resp = requests.put(self.fake_vault_url + '/v1/sys/leases/renew',
                            headers=headers,
                            json=payload)

        # TODO check Vault response when expired
        assert resp.status_code == 403

    @responses.activate
    def test_renew_self(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }

        payload = {
            'increment': 35
        }
        resp = requests.post(self.fake_vault_url + '/v1/auth/token/renew-self',
                             headers=headers,
                             json=payload)
        assert resp.json() == {
          "auth": {
            "client_token": '00000000-0000-0000-0000-000000000001',
            "policies": ['default', 'django-consumer'],
            "lease_duration": 35,
            "renewable": True,
          }
        }

    @responses.activate
    def test_lookup_self(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }
        resp = requests.get(self.fake_vault_url + '/v1/auth/token/lookup-self',
                            headers=headers)
        assert resp.json() == {
            'data': {
                'policies': ['default', 'django-consumer']
            }
        }

    @responses.activate
    def test_revoke_self(self):
        self.fake_vault.add_handlers(responses, self.fake_vault_url)
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }
        resp = requests.put(self.fake_vault_url + '/v1/auth/token/revoke-self',
                            headers=headers)
        assert resp.status_code == 200

        resp = requests.get(self.fake_vault_url + '/v1/auth/token/lookup-self',
                            headers=headers)
        assert resp.status_code == 403
