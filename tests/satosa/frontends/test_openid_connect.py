"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import copy
import json
from base64 import urlsafe_b64encode
from collections import Counter
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import pytest
from oic.oic.message import AuthorizationResponse, AuthorizationRequest, IdToken, ClaimsRequest, \
    Claims, AuthorizationErrorResponse, RegistrationResponse, RegistrationRequest, \
    ClientRegistrationErrorResponse, ProviderConfigurationResponse, AccessTokenRequest, AccessTokenResponse, \
    TokenErrorResponse, OpenIDSchema
from oic.oic.provider import TokenEndpoint, UserinfoEndpoint, RegistrationEndpoint
from saml2.authn_context import PASSWORD

from satosa.attribute_mapping import AttributeMapper
from satosa.exception import SATOSAAuthenticationError
from satosa.frontends.openid_connect import OpenIDConnectFrontend
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from tests.users import USERS
from tests.users import OIDC_USERS


INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}
BASE_URL = "https://op.example.com"
CLIENT_ID = "client1"
CLIENT_SECRET = "client_secret"
EXTRA_CLAIMS = {
    "eduPersonScopedAffiliation": {
        "saml": ["eduPersonScopedAffiliation"],
        "openid": ["eduperson_scoped_affiliation"],
    },
    "eduPersonPrincipalName": {
        "saml": ["eduPersonPrincipalName"],
        "openid": ["eduperson_principal_name"],
    },
}
EXTRA_SCOPES = {
    "eduperson": ["eduperson_scoped_affiliation", "eduperson_principal_name"]
}

class TestOpenIDConnectFrontend(object):
    @pytest.fixture
    def frontend_config(self, signing_key_path):
        config = {
            "signing_key_path": signing_key_path,
            "provider": {
                "response_types_supported": ["code", "id_token", "code id_token token"],
                "scopes_supported": ["openid", "email"]
            }
        }

        return config

    @pytest.fixture
    def frontend_config_with_extra_scopes(self, signing_key_path):
        config = {
            "signing_key_path": signing_key_path,
            "provider": {
                "response_types_supported": ["code", "id_token", "code id_token token"],
                "scopes_supported": ["openid", "email"],
                "extra_scopes": EXTRA_SCOPES,
            },
        }

        return config

    @pytest.fixture
    def frontend_config_with_extra_id_token_claims(self, signing_key_path):
        config = {
            "signing_key_path": signing_key_path,
            "provider": {
                "response_types_supported": ["code", "id_token", "code id_token token"],
                "scopes_supported": ["openid", "email"],
                "extra_id_token_claims": {
                    CLIENT_ID: ["email"],
                }
            },
        }

        return config

    def create_frontend(self, frontend_config):
        # will use in-memory storage
        instance = OpenIDConnectFrontend(lambda ctx, req: None,
                                         INTERNAL_ATTRIBUTES,
                                         frontend_config, BASE_URL, "oidc_frontend")
        instance.register_endpoints(["foo_backend"])
        return instance

    def create_frontend_with_extra_scopes(self, frontend_config_with_extra_scopes):
        # will use in-memory storage
        internal_attributes_with_extra_scopes = copy.deepcopy(INTERNAL_ATTRIBUTES)
        internal_attributes_with_extra_scopes["attributes"].update(EXTRA_CLAIMS)
        instance = OpenIDConnectFrontend(
            lambda ctx, req: None,
            internal_attributes_with_extra_scopes,
            frontend_config_with_extra_scopes,
            BASE_URL,
            "oidc_frontend_with_extra_scopes",
        )
        instance.register_endpoints(["foo_backend"])
        return instance

    @pytest.fixture
    def frontend(self, frontend_config):
        return self.create_frontend(frontend_config)

    @pytest.fixture
    def frontend_with_extra_scopes(self, frontend_config_with_extra_scopes):
        return self.create_frontend_with_extra_scopes(frontend_config_with_extra_scopes)

    @pytest.fixture
    def authn_req(self):
        state = "my_state"
        nonce = "nonce"
        redirect_uri = "https://client.example.com"
        claims_req = ClaimsRequest(id_token=Claims(email=None))
        req = AuthorizationRequest(client_id=CLIENT_ID, state=state, scope="openid",
                                   response_type="id_token", redirect_uri=redirect_uri,
                                   nonce=nonce, claims=claims_req)
        return req

    @pytest.fixture
    def authn_req_with_extra_scopes(self):
        state = "my_state"
        nonce = "nonce"
        redirect_uri = "https://client.example.com"
        claims_req = ClaimsRequest(id_token=Claims(email=None))
        req = AuthorizationRequest(
            client_id=CLIENT_ID,
            state=state,
            scope="openid email eduperson",
            response_type="id_token",
            redirect_uri=redirect_uri,
            nonce=nonce,
            claims=claims_req,
        )
        return req

    def insert_client_in_client_db(self, frontend, redirect_uri, extra_metadata={}):
        frontend.provider.clients = {
            CLIENT_ID: {"response_types": ["code", "id_token"],
                        "redirect_uris": [redirect_uri],
                        "client_secret": CLIENT_SECRET}}
        frontend.provider.clients[CLIENT_ID].update(extra_metadata)

    def insert_user_in_user_db(self, frontend, user_id):
        user_attributes = AttributeMapper(frontend.internal_attributes).to_internal(
            "saml", USERS["testuser1"]
        )
        frontend.user_db[user_id] = frontend.converter.from_internal(
            "openid", user_attributes
        )

    def create_access_token(self, frontend, user_id, auth_req):
        sub = frontend.provider.authz_state.get_subject_identifier('pairwise', user_id, 'client1.example.com')
        auth_req = AuthorizationRequest().from_dict(auth_req)
        access_token = frontend.provider.authz_state.create_access_token(auth_req, sub)
        return access_token.value

    def setup_for_authn_response(self, context, frontend, auth_req):
        context.state[frontend.name] = {"oidc_request": auth_req.to_urlencoded()}

        auth_info = AuthenticationInformation(
            PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml"
        )
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(
            frontend.internal_attributes
        ).to_internal("saml", USERS["testuser1"])
        internal_response.subject_id = USERS["testuser1"]["eduPersonTargetedID"][0]

        return internal_response

    def test_handle_authn_response(self, context, frontend, authn_req):
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]
        id_token = IdToken().from_jwt(resp["id_token"], key=[frontend.signing_key])
        assert id_token["iss"] == BASE_URL
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert "sub" in id_token
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert frontend.name not in context.state

    def test_handle_authn_request(self, context, frontend, authn_req):
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback
        client_name = "test client"
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"], {"client_name": client_name})

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)

        assert mock_callback.call_count == 1
        context, internal_req = mock_callback.call_args[0]
        assert internal_req.requester == authn_req["client_id"]
        assert internal_req.requester_name == [{"lang": "en", "text": client_name}]
        assert internal_req.subject_type == 'pairwise'
        assert internal_req.attributes == ["mail"]

    def test_handle_authn_request_with_extra_scopes(
        self, context, frontend_with_extra_scopes, authn_req_with_extra_scopes
    ):
        client_name = "test client"
        self.insert_client_in_client_db(
            frontend_with_extra_scopes,
            authn_req_with_extra_scopes["redirect_uri"],
            {"client_name": client_name},
        )

        context.request = dict(parse_qsl(authn_req_with_extra_scopes.to_urlencoded()))
        frontend_with_extra_scopes.handle_authn_request(context)
        internal_req = frontend_with_extra_scopes._handle_authn_request(context)
        assert internal_req.requester == authn_req_with_extra_scopes["client_id"]
        assert internal_req.requester_name == [{"lang": "en", "text": client_name}]
        assert internal_req.subject_type == "pairwise"
        assert sorted(internal_req.attributes) == [
            "eduPersonPrincipalName",
            "eduPersonScopedAffiliation",
            "mail",
        ]

    def test_get_approved_attributes(self, frontend):
        claims_req = ClaimsRequest(id_token=Claims(email=None), userinfo=Claims(userinfo_claim=None))
        req = AuthorizationRequest(scope="openid profile", claims=claims_req)
        provider_supported_claims = ["email", "name", "given_name", "family_name", "userinfo_claim", "extra_claim"]

        result = frontend._get_approved_attributes(provider_supported_claims, req)
        assert Counter(result) == Counter(["email", "name", "given_name", "family_name", "userinfo_claim"])

    def test_handle_backend_error(self, context, frontend):
        redirect_uri = "https://client.example.com"
        areq = AuthorizationRequest(client_id=CLIENT_ID, scope="openid", response_type="id_token",
                                    redirect_uri=redirect_uri)
        context.state[frontend.name] = {"oidc_request": areq.to_urlencoded()}

        # fake an error
        message = "test error"
        error = SATOSAAuthenticationError(context.state, message)
        resp = frontend.handle_backend_error(error)

        assert resp.message.startswith(redirect_uri)
        error_response = AuthorizationErrorResponse().deserialize(urlparse(resp.message).fragment)
        error_response["error"] = "access_denied"
        error_response["error_description"] == message

    def test_register_client(self, context, frontend):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["id_token"])
        context.request = registration_request.to_dict()
        registration_response = frontend.client_registration(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(registration_response.message, "json")
        assert "client_id" in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert reg_resp["response_types"] == ["id_token"]

    def test_register_client_with_wrong_response_type(self, context, frontend):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["id_token token"])
        context.request = registration_request.to_dict()
        registration_response = frontend.client_registration(context)
        assert registration_response.status == "400 Bad Request"
        error_response = ClientRegistrationErrorResponse().deserialize(
            registration_response.message, "json")
        assert error_response["error"] == "invalid_request"
        assert "response_type" in error_response["error_description"]

    def test_provider_configuration_endpoint(self, context, frontend):
        expected_capabilities = {
            "response_types_supported": ["code", "id_token", "code id_token token"],
            "jwks_uri": "{}/{}/jwks".format(BASE_URL, frontend.name),
            "authorization_endpoint": "{}/foo_backend/{}/authorization".format(BASE_URL, frontend.name),
            "token_endpoint": "{}/{}/token".format(BASE_URL, frontend.name),
            "userinfo_endpoint": "{}/{}/userinfo".format(BASE_URL, frontend.name),
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "claims_supported": ["email"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "issuer": BASE_URL,
            "require_request_uri_registration": False,
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "version": "3.0"
        }

        http_response = frontend.provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")

        provider_config_dict = provider_config.to_dict()
        scopes_supported = provider_config_dict.pop("scopes_supported")
        assert "eduperson" not in scopes_supported
        assert all(scope in scopes_supported for scope in ["openid", "email"])

        provider_items = provider_config_dict.items()
        expected_items = expected_capabilities.items()
        assert all(item in provider_items for item in expected_items)

    def test_provider_configuration_endpoint_with_extra_scopes(
        self, context, frontend_with_extra_scopes
    ):
        expected_capabilities = {
            "response_types_supported": ["code", "id_token", "code id_token token"],
            "jwks_uri": "{}/{}/jwks".format(BASE_URL, frontend_with_extra_scopes.name),
            "authorization_endpoint": "{}/foo_backend/{}/authorization".format(
                BASE_URL, frontend_with_extra_scopes.name
            ),
            "token_endpoint": "{}/{}/token".format(
                BASE_URL, frontend_with_extra_scopes.name
            ),
            "userinfo_endpoint": "{}/{}/userinfo".format(
                BASE_URL, frontend_with_extra_scopes.name
            ),
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "claims_supported": [
                "email",
                "eduperson_scoped_affiliation",
                "eduperson_principal_name",
            ],
            "grant_types_supported": ["authorization_code", "implicit"],
            "issuer": BASE_URL,
            "require_request_uri_registration": False,
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "version": "3.0",
        }

        http_response = frontend_with_extra_scopes.provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(
            http_response.message, "json"
        )

        provider_config_dict = provider_config.to_dict()
        scopes_supported = provider_config_dict.pop("scopes_supported")
        assert all(
            scope in scopes_supported for scope in ["openid", "email", "eduperson"]
        )

        provider_items = provider_config_dict.items()
        expected_items = expected_capabilities.items()
        assert all(item in provider_items for item in expected_items)

    def test_jwks(self, context, frontend):
        http_response = frontend.jwks(context)
        jwks = json.loads(http_response.message)
        assert jwks == {"keys": [frontend.signing_key.serialize()]}

    def test_register_endpoints_token_and_userinfo_endpoint_is_published_if_necessary(self, frontend):
        urls = frontend.register_endpoints(["test"])
        assert ("^{}/{}".format(frontend.name, TokenEndpoint.url), frontend.token_endpoint) in urls
        assert ("^{}/{}".format(frontend.name, UserinfoEndpoint.url), frontend.userinfo_endpoint) in urls

    def test_register_endpoints_token_and_userinfo_endpoint_is_not_published_if_only_implicit_flow(
            self, frontend_config, context):
        frontend_config["provider"]["response_types_supported"] = ["id_token", "id_token token"]
        frontend = self.create_frontend(frontend_config)

        urls = frontend.register_endpoints(["test"])
        assert ("^{}/{}".format("test", TokenEndpoint.url), frontend.token_endpoint) not in urls
        assert ("^{}/{}".format("test", UserinfoEndpoint.url), frontend.userinfo_endpoint) not in urls

        http_response = frontend.provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")
        assert "token_endpoint" not in provider_config

    @pytest.mark.parametrize("client_registration_enabled", [
        True,
        False
    ])
    def test_register_endpoints_dynamic_client_registration_is_configurable(
            self, frontend_config, client_registration_enabled):
        frontend_config["provider"]["client_registration_supported"] = client_registration_enabled
        frontend = self.create_frontend(frontend_config)

        urls = frontend.register_endpoints(["test"])
        assert (("^{}/{}".format(frontend.name, RegistrationEndpoint.url),
                 frontend.client_registration) in urls) == client_registration_enabled
        provider_info = ProviderConfigurationResponse().deserialize(frontend.provider_config(None).message, "json")
        assert ("registration_endpoint" in provider_info) == client_registration_enabled

    @pytest.mark.parametrize("sub_mirror_public", [
        True,
        False
    ])
    def test_mirrored_subject(self, context, frontend_config, authn_req, sub_mirror_public):
        frontend_config["sub_mirror_public"] = sub_mirror_public
        frontend_config["provider"]["subject_types_supported"] = ["public"]
        frontend = self.create_frontend(frontend_config)

        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        id_token = IdToken().from_jwt(resp["id_token"], key=[frontend.signing_key])
        if sub_mirror_public:
            assert id_token["sub"] == OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        else:
            assert id_token["sub"] != OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]

    def test_token_endpoint(self, context, frontend_config, authn_req):
        token_lifetime = 60 * 60 * 24
        frontend_config["provider"]["access_token_lifetime"] = token_lifetime
        frontend = self.create_frontend(frontend_config)

        user_id = "test_user"
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        self.insert_user_in_user_db(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_resp = frontend.provider.authorize(authn_req, user_id)

        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]

    def test_token_endpoint_with_extra_claims(self, context, frontend_config_with_extra_id_token_claims, authn_req):
        frontend = self.create_frontend(frontend_config_with_extra_id_token_claims)

        user_id = "test_user"
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        self.insert_user_in_user_db(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_resp = frontend.provider.authorize(authn_req, user_id)

        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]

        id_token = IdToken().from_jwt(parsed["id_token"], key=[frontend.signing_key])
        assert id_token["email"] == "test@example.com"

    def test_token_endpoint_issues_refresh_tokens_if_configured(self, context, frontend_config, authn_req):
        frontend_config["provider"]["refresh_token_lifetime"] = 60 * 60 * 24 * 365
        frontend = OpenIDConnectFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                         frontend_config, BASE_URL, "oidc_frontend")
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        self.insert_user_in_user_db(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_resp = frontend.provider.authorize(authn_req, user_id)

        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["refresh_token"]

    def test_token_endpoint_with_invalid_client_authentication(self, context, frontend, authn_req):
        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code="code").to_dict()
        credentials = "{}:{}".format("unknown", "unknown")
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "401 Unauthorized"
        assert parsed_message["error"] == "invalid_client"

    def test_token_endpoint_with_invalid_code(self, context, frontend, authn_req):
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code="invalid").to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "400 Bad Request"
        assert parsed_message["error"] == "invalid_grant"

    def test_userinfo_endpoint(self, context, frontend, authn_req):
        user_id = USERS["testuser1"]["eduPersonTargetedID"][0]
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        self.insert_user_in_user_db(frontend, user_id)

        authn_req["scope"] = "openid email"
        token = self.create_access_token(frontend, user_id, authn_req)
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.userinfo_endpoint(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"

    def test_userinfo_endpoint_with_extra_scopes(
        self, context, frontend_with_extra_scopes, authn_req_with_extra_scopes
    ):
        user_id = USERS["testuser1"]["eduPersonTargetedID"][0]
        self.insert_client_in_client_db(
            frontend_with_extra_scopes, authn_req_with_extra_scopes["redirect_uri"]
        )
        self.insert_user_in_user_db(frontend_with_extra_scopes, user_id)

        token = self.create_access_token(
            frontend_with_extra_scopes, user_id, authn_req_with_extra_scopes
        )
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend_with_extra_scopes.userinfo_endpoint(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"
        # TODO
        assert parsed["eduperson_scoped_affiliation"] == ["student@example.com"]
        assert parsed["eduperson_principal_name"] == ["test@example.com"]

    def test_userinfo_with_invalid_token(self, context, frontend):
        context.request = {}
        context.request_authorization = "Bearer invalid"

        response = frontend.userinfo_endpoint(context)
        assert response.status == "401 Unauthorized"

    def test_full_flow(self, context, frontend_with_extra_scopes):
        redirect_uri = "https://client.example.com/redirect"
        response_type = "code id_token token"
        mock_callback = Mock()
        frontend_with_extra_scopes.auth_req_callback_func = mock_callback
        # discovery
        http_response = frontend_with_extra_scopes.provider_config(context)
        _ = ProviderConfigurationResponse().deserialize(http_response.message, "json")

        # client registration
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri], response_types=[response_type])
        context.request = registration_request.to_dict()
        http_response = frontend_with_extra_scopes.client_registration(context)
        registration_response = RegistrationResponse().deserialize(http_response.message, "json")

        # authentication request
        authn_req = AuthorizationRequest(
            redirect_uri=redirect_uri,
            client_id=registration_response["client_id"],
            response_type=response_type,
            scope="openid email eduperson",
            state="state",
            nonce="nonce",
        )
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend_with_extra_scopes.handle_authn_request(context)
        assert mock_callback.call_count == 1

        # fake authentication response from backend
        internal_response = self.setup_for_authn_response(
            context, frontend_with_extra_scopes, authn_req
        )
        http_response = frontend_with_extra_scopes.handle_authn_response(
            context, internal_response
        )
        authn_resp = AuthorizationResponse().deserialize(urlparse(http_response.message).fragment, "urlencoded")
        assert "code" in authn_resp
        assert "access_token" in authn_resp
        assert "id_token" in authn_resp

        # token request
        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]).to_dict()
        credentials = "{}:{}".format(registration_response["client_id"], registration_response["client_secret"])
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        http_response = frontend_with_extra_scopes.token_endpoint(context)
        parsed = AccessTokenResponse().deserialize(http_response.message, "json")
        assert "access_token" in parsed
        assert "id_token" in parsed

        # userinfo request
        context.request = {}
        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        http_response = frontend_with_extra_scopes.userinfo_endpoint(context)
        parsed = OpenIDSchema().deserialize(http_response.message, "json")
        assert "email" in parsed
        assert "eduperson_principal_name" in parsed
        assert "eduperson_scoped_affiliation" in parsed
