import responses
from urllib.parse import urlparse
from werkzeug.test import Client
from werkzeug.wrappers import Response

from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig
from satosa.util import join_paths


class TestAccountLinking:
    def test_full_flow(self, satosa_config_dict, account_linking_module_config):
        api_url = "https://alservice.example.com/api"
        redirect_url = "https://alservice.examle.com/redirect"
        account_linking_module_config["config"]["api_url"] = api_url
        account_linking_module_config["config"]["redirect_url"] = redirect_url
        satosa_config_dict["MICRO_SERVICES"].insert(0, account_linking_module_config)
        base_path = urlparse(satosa_config_dict["BASE"]).path.lstrip("\n/")

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), Response)

        # incoming auth req
        http_resp = test_client.get("/{}/{}/request".format(satosa_config_dict["BACKEND_MODULES"][0]["name"],
                                                            satosa_config_dict["FRONTEND_MODULES"][0]["name"]))
        assert http_resp.status_code == 200

        with responses.RequestsMock() as rsps:
            # fake no previous account linking
            rsps.add(responses.GET, "{}/get_id".format(api_url), "test_ticket", status=404)

            # incoming auth resp
            http_resp = test_client.get("/{}/response".format(satosa_config_dict["BACKEND_MODULES"][0]["name"]))
            assert http_resp.status_code == 302
            assert http_resp.headers["Location"].startswith(redirect_url)

        with responses.RequestsMock() as rsps:
            # fake previous account linking
            rsps.add(responses.GET, "{}/get_id".format(api_url), "test_userid", status=200)

            # incoming account linking response
            http_resp = test_client.get(join_paths("/", base_path, "account_linking/handle_account_linking"))
            assert http_resp.status_code == 200
