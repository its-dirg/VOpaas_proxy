import json
import re
import time
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import oic
import pytest
import responses
from Cryptodome.PublicKey import RSA
from jwkest.jwk import RSAKey
from oic.oic.message import IdToken
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from satosa.backends.openid_connect import OpenIDConnectBackend, _create_client, STATE_KEY, NONCE_KEY
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

ISSUER = "https://provider.example.com"
CLIENT_ID = "test_client"
NONCE = "the nonce"


class TestOpenIDConnectBackend(object):
    @pytest.fixture(autouse=True)
    def create_backend(self, internal_attributes, backend_config):
        self.oidc_backend = OpenIDConnectBackend(Mock(), internal_attributes, backend_config, "base_url", "oidc", None,
                                                 None)

    @pytest.fixture
    def backend_config(self):
        return {
            "client": {
                "client_metadata": {
                    "client_id": CLIENT_ID,
                    "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
                    "application_type": "web",
                    "application_name": "SATOSA Test",
                    "contacts": ["ops@example.com"],
                    "redirect_uris": ["https://client.test.com/authz_cb"],
                    "response_types": ["code"],
                    "subject_type": "pairwise"
                },
                "auth_req_params": {
                    "response_type": "code id_token token",
                    "scope": "openid foo"
                }
            },
            "provider_metadata": {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorization",
                "token_endpoint": ISSUER + "/token",
                "userinfo_endpoint": ISSUER + "/userinfo",
                "registration_endpoint": ISSUER + "/registration",
                "jwks_uri": ISSUER + "/static/jwks"
            }
        }

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]}
            }
        }

    @pytest.fixture
    def userinfo(self):
        return {
            "given_name": "Test",
            "family_name": "Devsson",
            "email": "test_dev@example.com",
            "sub": "username"
        }

    @pytest.fixture(scope="session")
    def signing_key(self):
        return RSAKey(key=RSA.generate(2048), alg="RS256")

    def assert_expected_attributes(self, attr_map, user_claims, actual_attributes):
        expected_attributes = {}
        for out_attr, in_mapping in attr_map["attributes"].items():
            expected_attributes[out_attr] = [user_claims[in_mapping["openid"][0]]]

        assert actual_attributes == expected_attributes

    def setup_jwks_uri(self, jwks_uri, key):
        responses.add(
            responses.GET,
            jwks_uri,
            body=json.dumps({"keys": [key.serialize()]}),
            status=200,
            content_type="application/json")

    def setup_token_endpoint(self, token_endpoint_url, userinfo, signing_key):
        id_token_claims = {
            "iss": ISSUER,
            "sub": userinfo["sub"],
            "aud": CLIENT_ID,
            "nonce": NONCE,
            "exp": time.time() + 3600,
            "iat": time.time()
        }
        id_token = IdToken(**id_token_claims).to_jwt([signing_key], signing_key.alg)
        token_response = {
            "access_token": "SlAV32hkKG",
            "token_type": "Bearer",
            "refresh_token": "8xLOxBtZp8",
            "expires_in": 3600,
            "id_token": id_token
        }
        responses.add(responses.POST,
                      token_endpoint_url,
                      body=json.dumps(token_response),
                      status=200,
                      content_type="application/json")

    def setup_userinfo_endpoint(self, userinfo_endpoint_url, userinfo):
        responses.add(responses.GET,
                      userinfo_endpoint_url,
                      body=json.dumps(userinfo),
                      status=200,
                      content_type="application/json")

    def get_redirect_uri_path(self, backend_config):
        return urlparse(backend_config["client"]["client_metadata"]["redirect_uris"][0]).path.lstrip("/")

    @pytest.fixture
    def incoming_authn_response(self, context, backend_config):
        oidc_state = "my state"
        context.path = self.get_redirect_uri_path(backend_config)
        context.request = {
            "code": "F+R4uWbN46U+Bq9moQPC4lEvRd2De4o=",
            "state": oidc_state
        }

        state_data = {
            STATE_KEY: oidc_state,
            NONCE_KEY: NONCE
        }
        context.state[self.oidc_backend.name] = state_data
        return context

    def test_register_endpoints(self, backend_config):
        redirect_uri_path = self.get_redirect_uri_path(backend_config)
        url_map = self.oidc_backend.register_endpoints()
        regex, callback = url_map[0]
        assert re.search(regex, redirect_uri_path)
        assert callback == self.oidc_backend.response_endpoint

    def test_translate_response_to_internal_response(self, internal_attributes, userinfo):
        internal_response = self.oidc_backend._translate_response(userinfo, ISSUER)
        assert internal_response.subject_id == userinfo["sub"]
        self.assert_expected_attributes(internal_attributes, userinfo, internal_response.attributes)

    @responses.activate
    def test_response_endpoint(self, backend_config, internal_attributes, userinfo, signing_key, incoming_authn_response):
        self.setup_jwks_uri(backend_config["provider_metadata"]["jwks_uri"], signing_key)
        self.setup_token_endpoint(backend_config["provider_metadata"]["token_endpoint"], userinfo, signing_key)
        self.setup_userinfo_endpoint(backend_config["provider_metadata"]["userinfo_endpoint"], userinfo)

        self.oidc_backend.response_endpoint(incoming_authn_response)

        args = self.oidc_backend.auth_callback_func.call_args[0]
        assert isinstance(args[0], Context)
        assert isinstance(args[1], InternalData)
        self.assert_expected_attributes(internal_attributes, userinfo, args[1].attributes)

    def test_start_auth_redirects_to_provider_authorization_endpoint(self, context, backend_config):
        auth_response = self.oidc_backend.start_auth(context, None)
        assert isinstance(auth_response, Response)

        login_url = auth_response.message
        parsed = urlparse(login_url)
        assert login_url.startswith(backend_config["provider_metadata"]["authorization_endpoint"])
        auth_params = dict(parse_qsl(parsed.query))
        assert auth_params["scope"] == backend_config["client"]["auth_req_params"]["scope"]
        assert auth_params["response_type"] == backend_config["client"]["auth_req_params"]["response_type"]
        assert auth_params["client_id"] == backend_config["client"]["client_metadata"]["client_id"]
        assert auth_params["redirect_uri"] == backend_config["client"]["client_metadata"]["redirect_uris"][0]
        assert "state" in auth_params
        assert "nonce" in auth_params

    @responses.activate
    def test_entire_flow(self, context, backend_config, internal_attributes, userinfo):
        self.setup_userinfo_endpoint(backend_config["provider_metadata"]["userinfo_endpoint"], userinfo)
        auth_response = self.oidc_backend.start_auth(context, None)
        auth_params = dict(parse_qsl(urlparse(auth_response.message).query))

        access_token = 12345
        context.request = {
            "state": auth_params["state"],
            "access_token": access_token,
            "token_type": "Bearer",
        }
        self.oidc_backend.response_endpoint(context)
        args = self.oidc_backend.auth_callback_func.call_args[0]
        self.assert_expected_attributes(internal_attributes, userinfo, args[1].attributes)


class TestCreateClient(object):
    @pytest.fixture
    def provider_metadata(self):
        return {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/authorization",
            "token_endpoint": ISSUER + "/token",
            "registration_endpoint": ISSUER + "/registration"
        }

    @pytest.fixture
    def client_metadata(self):
        return {
            "client_id": "s6BhdRkqt3",
            "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            "application_type": "web",
            "redirect_uris":
                ["https://client.example.org/callback",
                 "https://client.example.org/callback2"],
            "client_name": "SATOSA Test",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_type": "pairwise",
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

    def assert_provider_metadata(self, provider_metadata, client):
        assert client.authorization_endpoint == provider_metadata["authorization_endpoint"]
        assert client.token_endpoint == provider_metadata["token_endpoint"]
        assert client.registration_endpoint == provider_metadata["registration_endpoint"]
        assert all(x in client.provider_info.to_dict().items() for x in provider_metadata.items())

    def assert_client_metadata(self, client_metadata, client):
        assert client.client_id == client_metadata["client_id"]
        assert client.client_secret == client_metadata["client_secret"]
        assert all(x in client.registration_response.to_dict().items() for x in client_metadata.items())

    def test_init(self, provider_metadata, client_metadata):
        client = _create_client(provider_metadata, client_metadata)
        assert isinstance(client, oic.oic.Client)
        assert client.client_authn_method == CLIENT_AUTHN_METHOD

    def test_supports_static_provider_discovery(self, provider_metadata, client_metadata):
        client = _create_client(provider_metadata, client_metadata)
        self.assert_provider_metadata(provider_metadata, client)

    @responses.activate
    def test_supports_dynamic_discovery(self, provider_metadata, client_metadata):
        responses.add(
            responses.GET,
            ISSUER + "/.well-known/openid-configuration",
            body=json.dumps(provider_metadata),
            status=200,
            content_type='application/json'
        )
        client = _create_client(dict(issuer=ISSUER), client_metadata)
        self.assert_provider_metadata(provider_metadata, client)

    def test_supports_static_client_registration(self, provider_metadata, client_metadata):
        client = _create_client(provider_metadata, client_metadata)
        self.assert_client_metadata(client_metadata, client)

    def test_supports_dynamic_client_registration(self, provider_metadata, client_metadata):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.add(
                responses.POST,
                provider_metadata["registration_endpoint"],
                body=json.dumps(client_metadata),
                status=200,
                content_type='application/json'
            )
            client = _create_client(provider_metadata, dict(redirect_uris=client_metadata["redirect_uris"]))

        self.assert_client_metadata(client_metadata, client)
