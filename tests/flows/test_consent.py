import json
import re

import responses
from urllib.parse import urlparse
from werkzeug.test import Client
from werkzeug.wrappers import Response

from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig
from satosa.util import join_paths


class TestConsent:
    def test_full_flow(self, satosa_config_dict, consent_module_config):
        api_url = "https://consent.example.com/api"
        redirect_url = "https://consent.example.com/redirect"
        consent_module_config["config"]["api_url"] = api_url
        consent_module_config["config"]["redirect_url"] = redirect_url
        satosa_config_dict["MICRO_SERVICES"].append(consent_module_config)
        base_path = urlparse(satosa_config_dict["BASE"]).path.lstrip("\n/")

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), Response)

        # incoming auth req
        http_resp = test_client.get("/{}/{}/request".format(satosa_config_dict["BACKEND_MODULES"][0]["name"],
                                                            satosa_config_dict["FRONTEND_MODULES"][0]["name"]))
        assert http_resp.status_code == 200

        verify_url_re = re.compile(r"{}/verify/\w+".format(api_url))
        with responses.RequestsMock() as rsps:
            # fake no previous consent

            consent_request_url_re = re.compile(r"{}/creq/\w+".format(api_url))
            rsps.add(responses.GET, verify_url_re, status=401)
            rsps.add(responses.GET, consent_request_url_re, "test_ticket", status=200)

            # incoming auth resp
            http_resp = test_client.get("/{}/response".format(satosa_config_dict["BACKEND_MODULES"][0]["name"]))
            assert http_resp.status_code == 302
            assert http_resp.headers["Location"].startswith(redirect_url)

        with responses.RequestsMock() as rsps:
            # fake consent
            rsps.add(responses.GET, verify_url_re, json.dumps({"foo": "bar"}), status=200)

            # incoming consent response
            http_resp = test_client.get(join_paths("/", base_path, "consent/handle_consent"))
            assert http_resp.status_code == 200
