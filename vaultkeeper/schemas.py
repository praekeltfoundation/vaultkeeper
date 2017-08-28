def vaultkeeper_schema():
    return {
        'definitions': {
            'daemon': {
                'type': 'object',
                'properties': {
                    'working_directory': {'type': 'string'},
                    'log_path': {'type': 'string'},
                    'credential_path': {'type': 'string'},
                    'lease_path': {'type': 'string'},
                    'refresh_interval': {'type': 'number'},
                    'renewal_grace': {'type': 'number'},
                },
                'required': [
                    'working_directory',
                    'log_path',
                    'credential_path',
                    'lease_path',
                    'refresh_interval',
                    'renewal_grace'
                ]
            },

            'gatekeeper': {
                'type': 'object',
                'properties': {
                    'gatekeeper_addr': {'type': 'string'}
                },
                'required': ['gatekeeper_addr']
            },

            'vault': {
                'type': 'object',
                'properties': {
                    'vault_addr': {'type': 'string'}
                },
                'required': ['vault_addr']
            },

            'app': {
                'type': 'object',
                'properties': {
                    'gunicorn_args': {'type': 'string'}
                },
                'required': ['gunicorn_args']
            },
        }
    }
