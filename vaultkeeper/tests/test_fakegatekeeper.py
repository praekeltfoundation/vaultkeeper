from fake_gatekeeper import FakeGatekeeper
import responses
import requests


class TestFakeGatekeeper(object):
    def setup(self):
        self.fake_gatekeeper = FakeGatekeeper()
        self.fake_gatekeeper.setup()
        self.fake_gatekeeper_url = 'https://test-gatekeeper-instance.net'

    @responses.activate
    def test_get_token(self):
        taskid = 'purple-rain-486-ab24134bed3423f124937'

        responses.add_callback(responses.POST,
                               self.fake_gatekeeper_url + '/token',
                               callback=self.fake_gatekeeper.get_token,
                               content_type='application/json')

        payload = {
            'task_id': taskid
        }

        resp = requests.post(self.fake_gatekeeper_url + '/token',
                             json=payload)

        assert resp.json() == {
            'ok': True,
            'token': '10000000-1000-1000-1000-100000000000'
        }
