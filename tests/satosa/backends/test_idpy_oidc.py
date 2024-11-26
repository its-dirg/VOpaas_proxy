import json
import re
import time
from datetime import datetime
from unittest.mock import Mock
from urllib.parse import parse_qsl
from urllib.parse import urlparse

from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.message.oidc import AuthorizationResponse
from idpyoidc.message.oidc import IdToken
from oic.oic import AuthorizationRequest
import pytest
import responses

from satosa.backends.idpy_oidc import IdpyOIDCBackend
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

ISSUER = "https://provider.example.com"
CLIENT_ID = "test_client"
CLIENT_BASE_URL = "https://client.test.com"
NONCE = "the nonce"


class TestIdpyOIDCBackend(object):
    @pytest.fixture
    def backend_config(self):
        return {
            "client": {
                "base_url": CLIENT_BASE_URL,
                "client_id": CLIENT_ID,
                "client_type": "oidc",
                "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
                "application_type": "web",
                "application_name": "SATOSA Test",
                "contacts": ["ops@example.com"],
                "response_types_supported": ["code"],
                "response_type": "code id_token token",
                "scope": "openid foo",
                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                "jwks_uri": f"{CLIENT_BASE_URL}/jwks.json",
                "provider_info": {
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authn",
                    "token_endpoint": f"{ISSUER}/token",
                    "userinfo_endpoint": f"{ISSUER}/user",
                    "jwks_uri": f"{ISSUER}/static/jwks"
                }
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

    @pytest.fixture(autouse=True)
    @responses.activate
    def create_backend(self, internal_attributes, backend_config):
        base_url = backend_config['client']['base_url']
        self.issuer_keys = build_keyjar(DEFAULT_KEY_DEFS)
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                backend_config['client']['provider_info']['jwks_uri'],
                body=self.issuer_keys.export_jwks_as_json(),
                status=200,
                content_type="application/json")

            self.oidc_backend = IdpyOIDCBackend(Mock(), internal_attributes, backend_config,
                                                base_url, "oidc")

    @pytest.fixture
    def userinfo(self):
        return {
            "given_name": "Test",
            "family_name": "Devsson",
            "email": "test_dev@example.com",
            "sub": "username"
        }

    @pytest.fixture
    def id_token(self, userinfo):
        issuer_keys = build_keyjar(DEFAULT_KEY_DEFS)
        signing_key = issuer_keys.get_signing_key(key_type='RSA')[0]
        signing_key.alg = "RS256"
        auth_time = int(datetime.utcnow().timestamp())
        id_token_claims = {
            "auth_time": auth_time,
            "iss": ISSUER,
            "sub": userinfo["sub"],
            "aud": CLIENT_ID,
            "nonce": NONCE,
            "exp": auth_time + 3600,
            "iat": auth_time,
        }
        id_token = IdToken(**id_token_claims)
        return id_token

    @pytest.fixture
    def all_user_claims(self, userinfo, id_token):
        all_user_claims = {**userinfo, **id_token}
        return all_user_claims

    def test_client(self, backend_config):
        assert isinstance(self.oidc_backend.client, StandAloneClient)
        # 3 signing keys. One RSA, one EC and one symmetric
        assert len(self.oidc_backend.client.context.keyjar.get_signing_key()) == 3
        assert self.oidc_backend.client.context.jwks_uri == backend_config['client']['jwks_uri']

    def assert_expected_attributes(self, attr_map, user_claims, actual_attributes):
        expected_attributes = {
            out_attr: [user_claims[in_mapping["openid"][0]]]
            for out_attr, in_mapping in attr_map["attributes"].items()
        }
        assert actual_attributes == expected_attributes

    def setup_token_endpoint(self, userinfo):
        _client = self.oidc_backend.client
        signing_key = self.issuer_keys.get_signing_key(key_type='RSA')[0]
        signing_key.alg = "RS256"
        id_token_claims = {
            "iss": ISSUER,
            "sub": userinfo["sub"],
            "aud": CLIENT_ID,
            "nonce": NONCE,
            "exp": time.time() + 3600,
            "iat": time.time()
        }
        id_token = IdToken(**id_token_claims).to_jwt([signing_key], algorithm=signing_key.alg)
        token_response = {
            "access_token": "SlAV32hkKG",
            "token_type": "Bearer",
            "refresh_token": "8xLOxBtZp8",
            "expires_in": 3600,
            "id_token": id_token
        }
        responses.add(responses.POST,
                      _client.context.provider_info['token_endpoint'],
                      body=json.dumps(token_response),
                      status=200,
                      content_type="application/json")

    def setup_userinfo_endpoint(self, userinfo):
        responses.add(responses.GET,
                      self.oidc_backend.client.context.provider_info['userinfo_endpoint'],
                      body=json.dumps(userinfo),
                      status=200,
                      content_type="application/json")

    @pytest.fixture
    def incoming_authn_response(self):
        _context = self.oidc_backend.client.context
        oidc_state = "my state"
        _uri = _context.claims.get_usage("redirect_uris")[0]
        _request = AuthorizationRequest(
            redirect_uri=_uri,
            response_type="code",
            client_id=_context.get_client_id(),
            scope=_context.claims.get_usage("scope"),
            nonce=NONCE
        )
        _context.cstate.set(oidc_state, {"iss": _context.issuer})
        _context.cstate.bind_key(NONCE, oidc_state)
        _context.cstate.update(oidc_state, _request)

        response = AuthorizationResponse(
            code="F+R4uWbN46U+Bq9moQPC4lEvRd2De4o=",
            state=oidc_state,
            iss=_context.issuer,
            nonce=NONCE
        )
        return response.to_dict()

    def test_register_endpoints(self):
        _uri = self.oidc_backend.client.context.claims.get_usage("redirect_uris")[0]
        redirect_uri_path = urlparse(_uri).path.lstrip('/')
        url_map = self.oidc_backend.register_endpoints()
        regex, callback = url_map[0]
        assert re.search(regex, redirect_uri_path)
        assert callback == self.oidc_backend.response_endpoint

    def test_translate_response_to_internal_response(self, all_user_claims):
        internal_response = self.oidc_backend._translate_response(all_user_claims, ISSUER)
        assert internal_response.subject_id == all_user_claims["sub"]
        self.assert_expected_attributes(
            self.oidc_backend.internal_attributes,
            all_user_claims,
            internal_response.attributes,
        )

    @responses.activate
    def test_response_endpoint(self, context, all_user_claims, incoming_authn_response):
        self.setup_token_endpoint(all_user_claims)
        self.setup_userinfo_endpoint(all_user_claims)

        response_context = Context()
        response_context.request = incoming_authn_response
        response_context.state = context.state

        self.oidc_backend.response_endpoint(response_context)

        args = self.oidc_backend.auth_callback_func.call_args[0]
        assert isinstance(args[0], Context)
        assert isinstance(args[1], InternalData)
        self.assert_expected_attributes(
            self.oidc_backend.internal_attributes, all_user_claims, args[1].attributes
        )

    def test_start_auth_redirects_to_provider_authorization_endpoint(self, context):
        _client = self.oidc_backend.client
        auth_response = self.oidc_backend.start_auth(context, None)
        assert isinstance(auth_response, Response)

        login_url = auth_response.message
        parsed = urlparse(login_url)
        assert login_url.startswith(_client.context.provider_info["authorization_endpoint"])
        auth_params = dict(parse_qsl(parsed.query))
        assert auth_params["scope"] == " ".join(_client.context.claims.get_usage("scope"))
        assert auth_params["response_type"] == _client.context.claims.get_usage("response_types")[0]
        assert auth_params["client_id"] == _client.client_id
        assert auth_params["redirect_uri"] == _client.context.claims.get_usage("redirect_uris")[0]
        assert "state" in auth_params
        assert "nonce" in auth_params
