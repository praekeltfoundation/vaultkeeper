from fake_vault import FakeVault
import responses
import requests
import json


class FakeGatekeeper(object):
    def setup(self):
        self.fake_vault = FakeVault()
        self.fake_vault.setup()
        self.vault_token = '00000000-0000-0000-0000-000000000000'
        self.policies = {
            'purple-rain-486': {
                'policies': ['default', 'django-consumer'],
                'ttl': 300
            }
        }

    def reload_policies(self):
        pass

    def task_authorised(self, taskid):
        for policies in self.policies:
            if taskid.startswith(policies):
                return True
        return False

    def get_token(self, request):
        taskid = json.loads(request.body)['task_id']
        if not self.task_authorised(taskid):
            return (401, {}, {})

        headers = {'content-type': 'application/json'}
        body = {
            'ok': True,
            'token': '10000000-1000-1000-1000-100000000000'
        }
        return (200, headers, json.dumps(body))
