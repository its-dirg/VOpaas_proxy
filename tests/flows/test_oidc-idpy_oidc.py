from copy import copy
import json
import time
from urllib.parse import urlparse, urlencode, parse_qsl
from unittest import mock
import mongomock
import pytest
from cryptojwt.key_jar import build_keyjar
from idpyoidc.message.oidc import IdToken, ClaimsRequest, Claims
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from requests.models import Response
from pyop.storage import StorageBase
from werkzeug.test import Client
from satosa.response import Response as satosaResp
from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig
from tests.users import USERS, OIDC_USERS


CLIENT_ID = "client1"
CLIENT_SECRET = "secret"
CLIENT_REDIRECT_URI = "https://client.example.com/cb"
REDIRECT_URI = "https://client.example.com/cb"
DB_URI = "mongodb://localhost/satosa"
ISSUER = "https://provider.example.com"
CLIENT_BASE_URL = "https://client.test.com"
NONCE = "the nonce"


@pytest.fixture
def oidc_frontend_config(signing_key_path):
    data = {
        "module": "satosa.frontends.openid_connect.OpenIDConnectFrontend",
        "name": "OIDCFrontend",
        "config": {
            "issuer": "https://proxy-op.example.com",
            "signing_key_path": signing_key_path,
            "provider": {
                "response_types_supported": ["id_token"],
                "claims_supported": ["email"],
            },
            "client_db_uri": DB_URI,  # use mongodb for integration testing
            "db_uri": DB_URI,  # use mongodb for integration testing
        },
    }

    return data


@pytest.fixture
def idpy_oidc_backend_config():
    data = {
        "module": "satosa.backends.idpy_oidc.IdpyOIDCBackend",
        "name": "OIDCBackend",
        "config": {
            "client": {
                "redirect_uris": ["http://example.com/OIDCBackend"],
                "base_url": CLIENT_BASE_URL,
                "client_id": CLIENT_ID,
                "client_type": "oidc",
                "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
                "application_type": "web",
                "application_name": "SATOSA Test",
                "contacts": ["ops@example.com"],
                "response_types_supported": ["code"],
                "front_channel_logout_uri": "https://test-proxy.com/OIDCBackend/front-channel-logout",
                "scopes_supported": ["openid", "profile", "email"],
                "subject_type_supported": ["public"],
                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                "jwks_uri": f"{CLIENT_BASE_URL}/jwks.json",
                "provider_info": {
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authn",
                    "token_endpoint": f"{ISSUER}/token",
                    "userinfo_endpoint": f"{ISSUER}/user",
                    "jwks_uri": f"{ISSUER}/static/jwks",
                    "frontchannel_logout_session_required": True,
                },
            }
        },
    }
    return data


@mongomock.patch(servers=(("localhost", 27017),))
class TestOIDCToIdpyOIDC:
    def _client_setup(self):
        """Insert client in mongodb."""
        self._cdb = StorageBase.from_uri(
            DB_URI, db_name="satosa", collection="clients", ttl=None
        )
        self._cdb[CLIENT_ID] = {
            "redirect_uris": [REDIRECT_URI],
            "response_types": ["id_token"],
        }

    @mock.patch("requests.post")
    @mock.patch("idpyoidc.client.oauth2.stand_alone_client.StandAloneClient.finalize")
    def test_full_flow_front_channel_logout_inmemory_storage(
        self,
        mock_stand_alone_client_finalize,
        mock_logout_post_request,
        satosa_config_dict,
        oidc_frontend_config,
        idpy_oidc_backend_config,
    ):
        self._client_setup()
        subject_id = "testuser1"

        # proxy config
        satosa_config_dict["FRONTEND_MODULES"] = [oidc_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [idpy_oidc_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {
            attr_name: {"openid": [attr_name]} for attr_name in USERS[subject_id]
        }
        satosa_config_dict['LOGOUT_ENABLED'] = True

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), satosaResp)

        # get frontend OP config info
        provider_config = json.loads(
            test_client.get("/.well-known/openid-configuration").data.decode("utf-8")
        )

        # create auth req
        claims_request = ClaimsRequest(
            id_token=Claims(**{k: None for k in USERS[subject_id]})
        )
        req_args = {
            "scope": "openid",
            "response_type": "id_token",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "nonce": "nonce",
            "claims": claims_request.to_json(),
        }
        auth_req = (
            urlparse(provider_config["authorization_endpoint"]).path
            + "?"
            + urlencode(req_args)
        )

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "302 Found"
        parsed_auth_req = dict(
            parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query)
        )

        # create auth resp
        self.issuer_keys = build_keyjar(DEFAULT_KEY_DEFS)
        signing_key = self.issuer_keys.get_signing_key(key_type="RSA")[0]
        signing_key.alg = "RS256"

        id_token_claims = {k: v for k, v in OIDC_USERS[subject_id].items()}
        id_token_claims["sub"] = subject_id
        id_token_claims["iat"] = time.time()
        id_token_claims["exp"] = time.time() + 3600
        id_token_claims["iss"] = ISSUER
        id_token_claims["aud"] = idpy_oidc_backend_config["config"]["client"][
            "client_id"
        ]
        id_token_claims["nonce"] = parsed_auth_req["nonce"]
        id_token = IdToken(**id_token_claims).to_jwt(
            [signing_key], algorithm=signing_key.alg
        )
        authn_resp = {"state": parsed_auth_req["state"], "id_token": id_token}

        # mock finalize method of idpy oidc due to signing key issue and add sid manually
        id_token_claims["sid"] = "30f8dae4-1da5-41bf-a801-5aad0648af8c"
        mock_stand_alone_client_finalize.return_value = {
            "userinfo": USERS[subject_id],
            "id_token": id_token_claims,
            "issuer": ISSUER,
        }

        # make auth resp to proxy
        redirect_uri_path = urlparse(
            idpy_oidc_backend_config["config"]["client"]["redirect_uris"][0]
        ).path
        authn_resp_req = redirect_uri_path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get(authn_resp_req)
        assert authn_resp.status == "303 See Other"

        # mock response from logout url of RP
        resp = Response()
        resp.status_code = 200
        mock_logout_post_request.return_value = resp

        # get session storage values before calling logout to verify successful logout later
        (
            backend_session_before_logout,
            frontend_session_before_logout,
            session_maps_before_logout,
        ) = get_session_storage_components_using_sid(
            test_client.application.app.app.storage,
            "30f8dae4-1da5-41bf-a801-5aad0648af8c",
        )

        # call front channel logout
        req_args = {"sid": "30f8dae4-1da5-41bf-a801-5aad0648af8c"}
        front_channel_logout_req = (
            urlparse(
                idpy_oidc_backend_config["config"]["client"]["front_channel_logout_uri"]
            ).path
            + "?"
            + urlencode(req_args)
        )
        logout_resp = test_client.get(front_channel_logout_req)
        assert logout_resp.status == "200 OK"

        # verify logout successful
        (
            backend_session_after_logout,
            frontend_session_after_logout,
            session_maps_after_logout,
        ) = get_session_storage_components_using_sid(
            test_client.application.app.app.storage,
            "30f8dae4-1da5-41bf-a801-5aad0648af8c",
        )
        assert backend_session_before_logout != backend_session_after_logout
        assert frontend_session_before_logout != frontend_session_after_logout
        assert session_maps_before_logout != session_maps_after_logout


def get_session_storage_components_using_sid(storage, sid):
    backend_session = storage.get_backend_session(sid)
    session_maps = copy(storage.session_maps)
    frontend_session = ""
    for session_map in session_maps:
        frontend_session = storage.get_backend_session(
            session_map.get("frontend_sid")
        )
    return backend_session, frontend_session, session_maps
