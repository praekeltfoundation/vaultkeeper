import re
import json
from urlparse import urlparse


class FakeVault(object):
    def setup(self):
        self.policies = {
            'default': {
                'auth/token/lookup-self': {
                    'capabilities': ['read']
                },
                'auth/token/renew-self': {
                    'capabilities': ['update']
                },
                'auth/token/revoke-self': {
                    'capabilities': ['update']
                },
                'sys/capabilities-self': {
                    'capabilities': ['update']
                },
                'sys/leases/renew': {
                    'capabilities': ['update']
                },
                'cubbyhole/*': {
                    'capabilities': [
                        'create',
                        'read',
                        'update',
                        'delete',
                        'list'
                    ]
                },
                'sys/wrapping/wrap': {
                    'capabilities': ['update']
                },
                'sys/wrapping/lookup': {
                    'capabilities': ['update']
                },
                'sys/wrapping/unwrap': {
                    'capabilities': ['update']
                },
            },
            'django-consumer': {
                'database/creds/postgresql_myschema_readonly': {
                    'capabilities': ['read', 'list']
                },
            },
            'gatekeeper': {
                'auth/token/create': {
                    'capabilities': ['create', 'read', 'sudo', 'update']
                },
                'auth/token/create/*': {
                    'capabilities': ['create', 'read', 'sudo', 'update']
                },
                'auth/token/create-orphan': {
                    'capabilities': ['create', 'read', 'sudo', 'update']
                },
                'secret/gatekeeper': {
                    'capabilities': ['read']
                },
            },
            'policy-maintainer': {
                'postgres/config/connection/': {
                    'capabilities': [
                        'create',
                        'update',
                        'delete'
                    ]
                },
                'postgres/roles/*': {
                    'capabilities': [
                        'create',
                        'read',
                        'update',
                        'delete',
                        'list'
                    ]
                },
            }
        }

        self.wrapped_tokens = {
            '10000000-1000-1000-1000-100000000000': {
                'data': '00000000-0000-0000-0000-000000000001',
                'wrap_ttl': '200s'
            }
        }

        self.tokens = {
            '00000000-0000-0000-0000-000000000000': {
                'policies': ['default', 'gatekeeper'],
                'ttl': '2h'
            },
            '00000000-0000-0000-0000-000000000001': {
                'policies': ['default', 'django-consumer'],
                'ttl': '2h'
            },
            '10000000-1000-1000-1000-100000000000': {
                'policies': ['default'],
                'ttl': '2h'
            }
        }

        self.leases = {
            'database/creds/postgresql_myschema_readonly/lease-id1': {
                'lease_duration': 100,
                'renewable': True,
                'expired': False
            }
        }

    # TODO: Check that this response is legit Vault emulation
    def create_wrapped_token(self, request):
        header_data = request.headers
        params = json.loads(request.body)
        client_token = header_data['x-vault-token']
        path = urlparse(request.url).path[4:]
        action = 'read'
        if not self.token_authorised(client_token, path, action, params):
            return (401, {}, {})

        headers = {'content-type': 'application/json'}
        data = {
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
        return (200, headers, json.dumps(data))

    # TODO: Check that this response is legit Vault emulation
    def unwrap_token(self, request):
        header_data = request.headers
        client_token = header_data['x-vault-token']
        path = urlparse(request.url).path[4:]
        action = 'update'
        params = {}
        if not (self.token_authorised(client_token, path, action, params)
                or client_token not in self.wrapped_tokens.keys()):
            return (401, {}, {})

        unwrapped = self.wrapped_tokens[client_token]['data']
        headers = {'content-type': 'application/json'}
        data = {
            'request_id': '',
            'lease_id': '',
            'lease_duration': 2592000,
            'renewable': True,
            'data': {
                'token': unwrapped
            },
            'warnings': None
        }
        return (200, headers, json.dumps(data))

    def token_authenticated(self, token):
        return token in self.tokens.keys()

    def token_authorised(self, token, path, action, params):
        authorised = False
        if self.token_authenticated(token):
            policyset = self.tokens[token]['policies']
            if path.endswith('/'):
                path = path[0:-1]
            for entry in policyset:
                for key in self.policies[entry].keys():
                    pattern = re.compile('^' + re.escape(path) + '[a-zA-Z0-9_\-]*$')
                    if key.endswith('/*'):
                        pattern = re.compile('^' + re.escape(path) + '[a-zA-Z0-9_\-/]*$')
                    match = pattern.match(str(key))
                    if not match:
                        continue
                    capabilities = self.policies[entry][key]['capabilities']
                    if 'deny' in capabilities:
                        authorised = False
                        break
                    if action in capabilities:
                        authorised = self.parameter_allowed(
                            self.policies[entry][key], params)
        return authorised

    def parameter_allowed(self, policy, params):
        if 'denied_parameters' in policy.keys():
            for key in params.keys():
                if key in policy['denied_parameters'].keys():
                    if params[key] in policy['denied_parameters'][key]:
                        return False
        if 'allowed_parameters' in policy.keys():
            for key in params.keys():
                if key not in policy['allowed_parameters'].keys():
                    return False
                if params[key] not in policy['allowed_parameters'][key]:
                    return False
        return True

    def get_db_creds(self, request):
        header_data = request.headers
        client_token = header_data['x-vault-token']
        path = urlparse(request.url).path[4:]
        action = 'read'
        params = {}
        if not self.token_authorised(client_token, path, action, params):
            # TODO: Proper errors
            return (401, {}, {})

        body = {
            'lease_id': 'database/creds/postgresql_myschema_readonly/lease-id1',
            'lease_duration': 100,
            'renewable': True,
            'data': {
                'username': 'testuser1',
                'password': 'testpass1'
            }
        }
        headers = {'content-type': 'application/json'}
        return (200, headers, json.dumps(body))

    def expire_lease(self):
        self.leases = {
            'database/creds/postgresql_myschema_readonly/lease-id1': {
                'lease_duration': 100,
                'renewable': True,
                'expired': True
            }
        }

    def renew_lease(self, request):
        header_data = request.headers
        client_token = header_data['x-vault-token']
        path = urlparse(request.url).path[4:]
        action = 'update'
        params = {}
        if not self.token_authorised(client_token, path, action, params):
            # TODO: Proper errors
            return (401, {}, {})

        data = json.loads(request.body)
        leaseid = data['lease_id']
        increment = data['increment']
        if leaseid not in self.leases.keys():
            body = {
                'errors': ['lease not found or lease is not renewable']
            }
            return (401, {}, json.dumps(body))

        if self.leases[leaseid]['expired']:
            return (401, {}, {})

        self.leases[leaseid]['lease_duration'] += increment
        headers = {'content-type': 'application/json'}
        body = {
            'lease_id': leaseid,
            'lease_duration': self.leases[leaseid]['lease_duration'],
            'renewable': True
        }
        return (200, headers, json.dumps(body))

    def lookup_self(self, request):
        header_data = request.headers
        client_token = header_data['x-vault-token']
        path = urlparse(request.url).path[4:]
        action = 'read'
        params = {}
        if not self.token_authorised(client_token, path, action, params):
            return (401, {}, {})

        headers = {'content-type': 'application/json'}
        body = {
            'data': {
                'policies': self.tokens[client_token]['policies']
            }
        }
        return (200, headers, json.dumps(body))
