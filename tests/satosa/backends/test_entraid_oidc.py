import json
import re
import time
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import pytest
import responses
from Cryptodome.PublicKey import RSA
from jwkest.jwk import RSAKey
from oic.oic.message import IdToken
from msal.oauth2cli.oidc import _nonce_hash

from satosa.backends.entraid_oidc import (
    EntraIDOIDCBackend,
    _create_client,
    _initiate_auth_code_flow,
    AUTH_CODE_FLOW_STATE_KEY,
)
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.internal import InternalData
from satosa.response import Response

VARIABLE_TENANT_BASE = "https://login.microsoftonline.com/{tenantid}"
TENANT_BOUND_BASE = "https://login.microsoftonline.com/common"

ISSUER = f"{VARIABLE_TENANT_BASE}/v2.0"

CLIENT_ID = "test_client"
NONCE = "HvEWnLsQNRGOkUxm"

CONFIGURATION_ENDPOINT = f"{TENANT_BOUND_BASE}/v2.0/.well-known/openid-configuration"
AUTHORIZATION_ENDPOINT = f"{TENANT_BOUND_BASE}/oauth2/v2.0/authorize"
TOKEN_ENDPOINT = f"{TENANT_BOUND_BASE}/oauth2/v2.0/token"
JWKS_ENDPOINT = f"{TENANT_BOUND_BASE}/discovery/v2.0/keys"


class TestEntraIDOIDCBackend:

    @pytest.fixture(autouse=True)
    def mock_responses(self):
        self.r_mock = responses.RequestsMock(assert_all_requests_are_fired=False)
        self.r_mock.start()
        yield
        self.r_mock.stop()
        self.r_mock.reset()

    @pytest.fixture(autouse=True)
    def create_backend(self, mock_responses, internal_attributes, backend_config):
        self.setup_configuration_endpoint()
        self.oidc_backend = EntraIDOIDCBackend(
            Mock(), internal_attributes, backend_config, "base_url", "microsoft"
        )

    @pytest.fixture
    def backend_config(self):
        return {
            "issuer": ISSUER,
            "redirect_uri": "https://client.test.com/entraid_oidc",
            "scopes": ["User.Read"],
            "client": {
                "init": {
                    "client_id": CLIENT_ID,
                    "client_credential": "satosa.credentials",
                    "authority": "https://login.microsoftonline.com/common",
                    "app_name": "SATOSA",
                },
                "auth_req_params": {
                    "scope": "User.Read offline_access openid profile",
                    "response_type": "code",
                },
            },
        }

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]},
            }
        }

    @pytest.fixture
    def userinfo(self):
        return {
            "given_name": "Test",
            "family_name": "Devsson",
            "email": "test_dev@example.com",
            "sub": "username",
        }

    @pytest.fixture(scope="session")
    def signing_key(self):
        return RSAKey(key=RSA.generate(2048), alg="RS256")

    def assert_expected_attributes(self, attr_map, user_claims, actual_attributes):
        expected_attributes = {}
        for out_attr, in_mapping in attr_map["attributes"].items():
            expected_attributes[out_attr] = [user_claims[in_mapping["openid"][0]]]

        assert actual_attributes == expected_attributes

    def setup_jwks_uri(self, key, body=None):
        self.r_mock.add(
            responses.GET,
            JWKS_ENDPOINT,
            body=json.dumps(body) if body else json.dumps({"keys": [key.serialize()]}),
            status=200,
            content_type="application/json",
        )

    def setup_configuration_endpoint(self):
        self.r_mock.add(
            responses.GET,
            CONFIGURATION_ENDPOINT,
            body="""{
                "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "private_key_jwt",
                    "client_secret_basic"
                ],
                "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
                "response_modes_supported": [
                    "query",
                    "fragment",
                    "form_post"
                ],
                "subject_types_supported": [
                    "pairwise"
                ],
                "id_token_signing_alg_values_supported": [
                    "RS256"
                ],
                "response_types_supported": [
                    "code",
                    "id_token",
                    "code id_token",
                    "id_token token"
                ],
                "scopes_supported": [
                    "openid",
                    "profile",
                    "email",
                    "offline_access"
                ],
                "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
                "request_uri_parameter_supported": false,
                "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
                "authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "device_authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
                "http_logout_supported": true,
                "frontchannel_logout_supported": true,
                "end_session_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/logout",
                "claims_supported": [
                    "sub",
                    "iss",
                    "cloud_instance_name",
                    "cloud_instance_host_name",
                    "cloud_graph_host_name",
                    "msgraph_host",
                    "aud",
                    "exp",
                    "iat",
                    "auth_time",
                    "acr",
                    "nonce",
                    "preferred_username",
                    "name",
                    "tid",
                    "ver",
                    "at_hash",
                    "c_hash",
                    "email"
                ],
                "kerberos_endpoint": "https://login.microsoftonline.com/common/kerberos",
                "tenant_region_scope": null,
                "cloud_instance_name": "microsoftonline.com",
                "cloud_graph_host_name": "graph.windows.net",
                "msgraph_host": "graph.microsoft.com",
                "rbac_url": "https://pas.windows.net"
            }""",
            status=200,
            content_type="application/json",
        )

    def setup_token_endpoint(self, userinfo, signing_key, nonce=NONCE, body=None):
        id_token_claims = {
            "iss": ISSUER,
            "sub": userinfo["sub"],
            "given_name": userinfo["given_name"],
            "family_name": userinfo["family_name"],
            "email": userinfo["email"],
            "aud": CLIENT_ID,
            "nonce": _nonce_hash(nonce),
            "exp": time.time() + 3600,
            "iat": time.time(),
        }
        id_token = IdToken(**id_token_claims).to_jwt([signing_key], signing_key.alg)
        token_response = {
            "access_token": "SlAV32hkKG",
            "token_type": "Bearer",
            "refresh_token": "8xLOxBtZp8",
            "expires_in": 3600,
            "id_token": id_token,
        }
        self.r_mock.add(
            responses.POST,
            TOKEN_ENDPOINT,
            body=json.dumps(body) if body else json.dumps(token_response),
            status=200,
            content_type="application/json",
        )

    def get_redirect_uri_path(self, backend_config):
        return urlparse(backend_config["redirect_uri"]).path.lstrip("/")

    @pytest.fixture
    def incoming_authn_response(self, context, backend_config):
        csrf_protection = "some-random-value"
        client = _create_client(backend_config)
        auth_code_flow = _initiate_auth_code_flow(
            client,
            scopes=backend_config["scopes"],
            redirect_uri=backend_config["redirect_uri"],
            state=csrf_protection,
        )

        context.path = self.get_redirect_uri_path(backend_config)
        context.request = {
            "code": "F+R4uWbN46U+Bq9moQPC4lEvRd2De4o=",
            "state": csrf_protection,
        }

        state_data = {AUTH_CODE_FLOW_STATE_KEY: auth_code_flow}
        context.state[self.oidc_backend.name] = state_data
        return context

    def test_register_endpoints(self, backend_config):
        redirect_uri_path = self.get_redirect_uri_path(backend_config)
        url_map = self.oidc_backend.register_endpoints()
        regex, callback = url_map[0]
        assert re.search(regex, redirect_uri_path)
        assert callback == self.oidc_backend.response_endpoint

    def test_translate_response_to_internal_response(
        self, internal_attributes, userinfo
    ):
        internal_response = self.oidc_backend._translate_response(userinfo, ISSUER)
        assert internal_response.subject_id == userinfo["sub"]
        self.assert_expected_attributes(
            internal_attributes, userinfo, internal_response.attributes
        )

    def test_response_endpoint(
        self, internal_attributes, userinfo, signing_key, incoming_authn_response
    ):
        self.setup_configuration_endpoint()
        self.setup_jwks_uri(signing_key)
        # We can't easily control what nonce is created, but we can re-use the one they create in our test
        nonce = incoming_authn_response.state[self.oidc_backend.name][
            AUTH_CODE_FLOW_STATE_KEY
        ]["nonce"]
        self.setup_token_endpoint(userinfo, signing_key, nonce=nonce)

        self.oidc_backend.response_endpoint(incoming_authn_response)

        args = self.oidc_backend.auth_callback_func.call_args[0]
        assert isinstance(args[0], Context)
        assert isinstance(args[1], InternalData)
        self.assert_expected_attributes(
            internal_attributes, userinfo, args[1].attributes
        )

    def test_token_error(
        self, internal_attributes, userinfo, signing_key, incoming_authn_response
    ):
        self.setup_configuration_endpoint()
        self.setup_jwks_uri(
            signing_key,            
        )
        # We can't easily control what nonce is created, but we can re-use the one they create in our test
        nonce = incoming_authn_response.state[self.oidc_backend.name][
            AUTH_CODE_FLOW_STATE_KEY
        ]["nonce"]
        self.setup_token_endpoint(userinfo, signing_key, nonce=nonce, body={
            "error_description": "Unrecognised token type",
            "error": "server_error",
        },)

        with pytest.raises(SATOSAAuthenticationError):
            self.oidc_backend.response_endpoint(incoming_authn_response)
        

    def test_start_auth_redirects_to_provider_authorization_endpoint(
        self, context, backend_config
    ):
        auth_response = self.oidc_backend.start_auth(context, None)
        assert isinstance(auth_response, Response)

        login_url = auth_response.message
        parsed = urlparse(login_url)

        assert login_url.startswith(AUTHORIZATION_ENDPOINT)
        auth_params = dict(parse_qsl(parsed.query))
        assert (
            auth_params["scope"] == backend_config["client"]["auth_req_params"]["scope"]
        )
        assert (
            auth_params["response_type"]
            == backend_config["client"]["auth_req_params"]["response_type"]
        )
        assert auth_params["client_id"] == backend_config["client"]["init"]["client_id"]
        assert auth_params["redirect_uri"] == backend_config["redirect_uri"]
        assert "state" in auth_params
        assert "nonce" in auth_params
        assert "code_challenge" in auth_params

    def test_entire_flow(self, context, signing_key, internal_attributes, userinfo):
        auth_response = self.oidc_backend.start_auth(context, None)
        nonce = context.state[self.oidc_backend.name][AUTH_CODE_FLOW_STATE_KEY]["nonce"]
        self.setup_token_endpoint(userinfo, signing_key, nonce=nonce)
        auth_params = dict(parse_qsl(urlparse(auth_response.message).query))

        access_token = 12345
        context.request = {
            "state": auth_params["state"],
            "access_token": access_token,
            "token_type": "Bearer",
            "code": "F+R4uWbN46U+Bq9moQPC4lEvRd2De4o=",
        }
        self.oidc_backend.response_endpoint(context)
        args = self.oidc_backend.auth_callback_func.call_args[0]
        self.assert_expected_attributes(
            internal_attributes, userinfo, args[1].attributes
        )
