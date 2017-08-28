import pytest
import requests
import responses

from fake_vault import FakeVault


class TestFakeVault(object):
    def setup(self):
        self.fake_vault = FakeVault()
        self.fake_vault.setup()
        self.fake_vault_url = 'https://test-vault-instance.net'

    @pytest.mark.order1
    @responses.activate
    def test_get_wrapped_token(self):
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000000',
            'X-Vault-Wrap-TTL': '20s'
        }
        responses.add_callback(responses.POST,
                               self.fake_vault_url + '/v1/auth/token/create/',
                               callback=self.fake_vault.create_wrapped_token,
                               content_type='application/json')
        payload = {
            'policies': ['default', 'django-consumer'],
            'ttl': '1h',
            'renewable': True
        }

        resp = requests.post(self.fake_vault_url + '/v1/auth/token/create/',
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

    @pytest.mark.order2
    @responses.activate
    def test_unwrap_token(self):
        headers = {
            'X-Vault-Token': '10000000-1000-1000-1000-100000000000'
        }
        responses.add_callback(responses.POST,
                               self.fake_vault_url + '/v1/sys/wrapping/unwrap',
                               callback=self.fake_vault.unwrap_token,
                               content_type='application/json')

        resp = requests.post(self.fake_vault_url + '/v1/sys/wrapping/unwrap',
                             headers=headers)

        assert resp.json() == {
            'request_id': '',
            'lease_id': '',
            'lease_duration': 2592000,
            'renewable': True,
            'data': {
                'token': '00000000-0000-0000-0000-000000000001'
            },
            'warnings': None
        }

    @pytest.mark.order3
    @responses.activate
    def test_authenticated(self):
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }
        responses.add_callback(responses.GET,
                               self.fake_vault_url + '/v1/auth/token/lookup-self',
                               callback=self.fake_vault.lookup_self,
                               content_type='application/json')
        resp = requests.get(self.fake_vault_url + '/v1/auth/token/lookup-self',
                            headers=headers)
        assert resp.json() == {
            'data': {
                'policies': ['default', 'django-consumer']
            }
        }

    @pytest.mark.order4
    @responses.activate
    def test_get_psql_creds(self):
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }
        responses.add_callback(responses.GET,
                               self.fake_vault_url + '/v1/database/creds/postgresql_myschema_readonly',
                               callback=self.fake_vault.get_db_creds,
                               content_type='application/json')

        resp = requests.get(self.fake_vault_url + '/v1/database/creds/postgresql_myschema_readonly',
                            headers=headers)

        assert resp.json() == {
            'lease_id': 'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 100,
            'renewable': True,
            'data': {
                'username': 'testuser1',
                'password': 'testpass1'
            }
        }

    @pytest.mark.order5
    @responses.activate
    def test_renew_lease(self):
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }
        responses.add_callback(responses.PUT,
                               self.fake_vault_url + '/v1/sys/leases/renew',
                               callback=self.fake_vault.renew_lease,
                               content_type='application/json')
        payload = {
            'lease_id': 'database/creds/postgresql_myschema_readonly/lease-id1',
            'increment': 30
        }
        resp = requests.put(self.fake_vault_url + '/v1/sys/leases/renew',
                            headers=headers,
                            json=payload)

        assert resp.json() == {
            'lease_id': 'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 130,
            'renewable': True
        }

    # Only call this after more than 100 seconds have elapsed after test_renew_lease
    @pytest.mark.order6
    @responses.activate
    def test_renew_expired_lease(self):
        self.fake_vault.expire_lease()
        headers = {
            'X-Vault-Token': '00000000-0000-0000-0000-000000000001'
        }

        responses.add_callback(responses.PUT,
                               self.fake_vault_url + '/v1/sys/leases/renew/',
                               callback=self.fake_vault.renew_lease,
                               content_type='application/json')

        payload = {
            'lease_id': 'database/creds/postgresql/postgresql_myschema_readonly/lease-id1',
            'increment': 30
        }
        resp = requests.put(self.fake_vault_url + '/v1/sys/leases/renew/',
                            headers=headers,
                            json=payload)

        # TODO check Vault response when expired
        assert resp.status_code == 401
