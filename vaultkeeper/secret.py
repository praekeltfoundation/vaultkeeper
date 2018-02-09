import json
import time


class Secret(object):
    def __init__(self, name, backend):
        self.name = name
        self.backend = backend
        self.last_renewed = None
        self.endpoint = None
        self.vault_path = None
        self.policy = None
        self.lease_id = None
        self.lease_duration = None
        self.max_ttl = None
        self.renewable = None

    def constructor(self, **kwargs):
        self.endpoint = kwargs['endpoint']
        self.vault_path = kwargs['vault_path']
        self.policy = kwargs['policy']

    def add_secret(self, hvac_data):
        self.lease_id = hvac_data['lease_id']
        self.lease_duration = hvac_data['lease_duration']
        self.renewable = hvac_data['renewable']

    def update_lease(self, lease_id, lease_duration):
        self.lease_id = lease_id
        self.lease_duration = lease_duration
        self.last_renewed = time.time()

    def printable(self):
        return {
                'id': self.name,
                'backend': self.backend,
                'endpoint': self.endpoint,
                'vault_path': self.vault_path,
                'policy': self.policy,
                'renewable': self.renewable,
                'lease_id': self.lease_id,
                'lease_duration': self.lease_duration
        }


class Generic(Secret):
    def __init__(self, name, backend):
        Secret.__init__(self, name, backend)
        self.secret_value = None

    def constructor(self, **kwargs):
        Secret.constructor(self, **kwargs)

    def add_secret(self, hvac_data):
        Secret.add_secret(self, hvac_data)
        self.secret_value = hvac_data['data']

    def printable(self):
        output = Secret.printable(self)
        output['secret_value'] = self.secret_value
        return output


class Token(Secret):
    def __init__(self, name, backend):
        Secret.__init__(self, name, backend)
        self.token_value = None

    def constructor(self, **kwargs):
        Secret.constructor(self, **kwargs)

    def add_secret(self, hvac_data):
        Secret.add_secret(self, hvac_data)
        self.token_value = hvac_data['data']['token']

    def update_ttl(self, ttl):
        self.lease_duration = ttl

    def printable(self):
        output = Secret.printable(self)
        output['token_value'] = self.token_value
        return output


class UnwrappedToken(Secret):
    def __init__(self, name, backend):
        Secret.__init__(self, name, backend)
        self.token_value = None

    def constructor(self, **kwargs):
        Secret.constructor(self, **kwargs)

    def add_secret(self, hvac_data):
        self.lease_duration = hvac_data['auth']['lease_duration']
        self.renewable = hvac_data['auth']['renewable']
        self.token_value = hvac_data['auth']['client_token']

    def update_ttl(self, ttl):
        self.lease_duration = ttl

    def printable(self):
        output = Secret.printable(self)
        output['token_value'] = self.token_value
        return output


class Database(Secret):
    def __init__(self, name, backend):
        Secret.__init__(self, name, backend)
        self.username = None
        self.password = None
        self.schema = None

    def constructor(self, **kwargs):
        Secret.constructor(self, **kwargs)
        self.schema = kwargs['schema']

    def add_secret(self, hvac_data):
        Secret.add_secret(self, hvac_data)
        self.username = hvac_data['data']['username']
        self.password = hvac_data['data']['password']

    def printable(self):
        output = Secret.printable(self)
        output['username'] = self.username
        output['password'] = self.password
        return output


class PostgreSQL(Database):
    def __init__(self, name, backend):
        Database.__init__(self, name, backend)
        self.username = None
        self.password = None
        self.schema = None

    def constructor(self, **kwargs):
        Database.constructor(self, **kwargs)
        self.setrole = kwargs['set_role']

    def add_secret(self, hvac_data):
        Database.add_secret(self, hvac_data)
        self.username = hvac_data['data']['username']
        self.password = hvac_data['data']['password']

    def printable(self):
        output = Database.printable(self)
        output['set_role'] = self.setrole
        return output


class RabbitMQ(Secret):
    def __init__(self, name, backend):
        Secret.__init__(self, name, backend)
        self.username = None
        self.password = None
        self.vhost = None

    def constructor(self, **kwargs):
        Secret.constructor(self, **kwargs)
        self.vhost = kwargs['vhost']

    def add_secret(self, hvac_data):
        Secret.add_secret(self, hvac_data)
        self.username = hvac_data['data']['username']
        self.password = hvac_data['data']['password']

    def printable(self):
        output = Secret.printable(self)
        output['username'] = self.username
        output['password'] = self.password
        return output


class AWS(Secret):
    def __init__(self, name='', backend=''):
        Secret.__init__(self, name, backend)
        self.access_key = None
        self.secret_key = None
        self.security_token = None
        self.region = None

    def constructor(self, **kwargs):
        Secret.constructor(self, **kwargs)
        self.region = kwargs['region']

    def add_secret(self, hvac_data):
        Secret.add_secret(self, hvac_data)
        self.access_key = hvac_data['data']['access_key']
        self.secret_key = hvac_data['data']['secret_key']
        self.security_token = hvac_data['data']['security_token']

    def printable(self):
        output = Secret.printable(self)
        output['access_key'] = self.access_key
        output['secret_key'] = self.secret_key
        output['security_token'] = self.security_token
        return output


def parse_secret_file(config_path):
    with open(config_path) as consumer_config:
        data = json.load(consumer_config)
    secrets = {}
    for entry in data:
        name = entry['id']
        backend = entry['backend']
        cls = classnames[str(backend)]
        inst = cls(name, backend)
        inst.constructor(**entry)
        secrets[name] = inst
    return secrets


def parse_secret_data(data):
    secrets = {}
    for entry in data:
        name = entry['id']
        backend = entry['backend']
        cls = classnames[str(backend)]
        inst = cls(name, backend)
        inst.constructor(**entry)
        secrets[name] = inst
    return secrets


def printable_secrets(secrets):
    output = []
    for name, secret in secrets.iteritems():
        output.append(secret.printable())
    return output


classnames = {
    'database': Database,
    'postgresql': PostgreSQL,
    'rabbitmq': RabbitMQ,
    'aws': AWS,
    'token': Token,
}
