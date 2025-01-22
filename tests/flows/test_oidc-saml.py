import os
import json
import base64
from urllib.parse import urlparse, urlencode, parse_qsl

import mongomock
import pytest
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS
from oic.oic.message import ClaimsRequest, Claims
from pyop.storage import StorageBase
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from werkzeug.test import Client
from werkzeug.wrappers import Response

from satosa.metadata_creation.saml_metadata import create_entity_descriptors
from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig
from satosa.util import join_paths
from tests.users import USERS
from tests.users import OIDC_USERS
from tests.util import FakeIdP


CLIENT_ID = "client1"
CLIENT_SECRET = "secret"
CLIENT_REDIRECT_URI = "https://client.example.com/cb"
REDIRECT_URI = "https://client.example.com/cb"
DB_URI = "mongodb://localhost/satosa"
EXTRA_ISSUER = "<base_url>/other/op"

@pytest.fixture(scope="session")
def client_db_path(tmpdir_factory):
    tmpdir = str(tmpdir_factory.getbasetemp())
    path = os.path.join(tmpdir, "cdb.json")
    cdb_json = {
        CLIENT_ID: {
            "response_types": ["id_token", "code"],
            "redirect_uris": [
                CLIENT_REDIRECT_URI
            ],
            "client_secret": CLIENT_SECRET
        }
    }
    with open(path, "w") as f:
        f.write(json.dumps(cdb_json))

    return path

@pytest.fixture
def oidc_frontend_config(signing_key_path):
    data = {
        "module": "satosa.frontends.openid_connect.OpenIDConnectFrontend",
        "name": "OIDCFrontend",
        "config": {
            "signing_key_path": signing_key_path,
            "provider": {"response_types_supported": ["id_token"]},
            "client_db_uri": DB_URI,  # use mongodb for integration testing
            "db_uri": DB_URI  # use mongodb for integration testing
        }
    }

    return data


@pytest.fixture
def oidc_stateless_frontend_config(signing_key_path, client_db_path):
    data = {
        "module": "satosa.frontends.openid_connect.OpenIDConnectFrontend",
        "name": "OIDCFrontend",
        "config": {
            "signing_key_path": signing_key_path,
            "client_db_path": client_db_path,
            "db_uri": "stateless://user:abc123@localhost",
            "provider": {
                "response_types_supported": ["id_token", "code"]
            }
        }
    }

    return data


@mongomock.patch(servers=(('localhost', 27017),))
class TestOIDCToSAML:
    def _client_setup(self):
        """Insert client in mongodb."""
        self._cdb = StorageBase.from_uri(
            DB_URI, db_name="satosa", collection="clients", ttl=None
        )
        self._cdb[CLIENT_ID] = {
            "redirect_uris": [REDIRECT_URI],
            "response_types": ["id_token"]
        }

    def _discover_provider(self, client, provider):
        discovery_path = (
            join_paths(urlparse(provider).path, ".well-known/openid-configuration")
        )
        return json.loads(client.get(discovery_path).data.decode("utf-8"))

    def test_full_flow(self, satosa_config_dict, oidc_frontend_config, saml_backend_config, idp_conf):
        self._client_setup()
        subject_id = "testuser1"

        # proxy config
        oidc_frontend_config["config"]["provider"]["issuer"] = EXTRA_ISSUER
        satosa_config_dict["FRONTEND_MODULES"] = [oidc_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {attr_name: {"openid": [attr_name],
                                                                               "saml": [attr_name]}
                                                                   for attr_name in USERS[subject_id]}
        _, backend_metadata = create_entity_descriptors(SATOSAConfig(satosa_config_dict))

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), Response)

        # get frontend OP config info
        issuer = EXTRA_ISSUER.replace("<base_url>", satosa_config_dict["BASE"])
        provider_config = self._discover_provider(test_client, issuer)

        # create auth req
        claims_request = ClaimsRequest(id_token=Claims(**{k: None for k in USERS[subject_id]}))
        req_args = {"scope": "openid", "response_type": "id_token", "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI, "nonce": "nonce",
                    "claims": claims_request.to_json()}
        auth_req = urlparse(provider_config["authorization_endpoint"]).path + "?" + urlencode(req_args)

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "303 See Other"

        # config test IdP
        backend_metadata_str = str(backend_metadata[saml_backend_config["name"]][0])
        idp_conf["metadata"]["inline"].append(backend_metadata_str)
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf))

        # create auth resp
        req_params = dict(parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query))
        url, authn_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            subject_id,
            response_binding=BINDING_HTTP_REDIRECT)

        # make auth resp to proxy
        authn_resp_req = urlparse(url).path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get(authn_resp_req)
        assert authn_resp.status == "303 See Other"

        # verify auth resp from proxy
        resp_dict = dict(parse_qsl(urlparse(authn_resp.data.decode("utf-8")).fragment))
        signing_key = RSAKey(key=rsa_load(oidc_frontend_config["config"]["signing_key_path"]),
                             use="sig", alg="RS256")
        id_token_claims = JWS().verify_compact(resp_dict["id_token"], keys=[signing_key])

        assert all(
            (name, values) in id_token_claims.items()
            for name, values in OIDC_USERS[subject_id].items()
        )

    def test_full_stateless_id_token_flow(self, satosa_config_dict, oidc_stateless_frontend_config, saml_backend_config, idp_conf):
        subject_id = "testuser1"

        # proxy config
        satosa_config_dict["FRONTEND_MODULES"] = [oidc_stateless_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {attr_name: {"openid": [attr_name],
                                                                               "saml": [attr_name]}
                                                                   for attr_name in USERS[subject_id]}
        _, backend_metadata = create_entity_descriptors(SATOSAConfig(satosa_config_dict))

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), Response)

        # get frontend OP config info
        issuer = satosa_config_dict["BASE"]
        provider_config = self._discover_provider(test_client, issuer)

        # create auth req
        claims_request = ClaimsRequest(id_token=Claims(**{k: None for k in USERS[subject_id]}))
        req_args = {"scope": "openid", "response_type": "id_token", "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI, "nonce": "nonce",
                    "claims": claims_request.to_json()}
        auth_req = urlparse(provider_config["authorization_endpoint"]).path + "?" + urlencode(req_args)

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "303 See Other"

        # config test IdP
        backend_metadata_str = str(backend_metadata[saml_backend_config["name"]][0])
        idp_conf["metadata"]["inline"].append(backend_metadata_str)
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf))

        # create auth resp
        req_params = dict(parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query))
        url, authn_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            subject_id,
            response_binding=BINDING_HTTP_REDIRECT)

        # make auth resp to proxy
        authn_resp_req = urlparse(url).path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get(authn_resp_req)
        assert authn_resp.status == "303 See Other"

        # verify auth resp from proxy
        resp_dict = dict(parse_qsl(urlparse(authn_resp.data.decode("utf-8")).fragment))
        signing_key = RSAKey(key=rsa_load(oidc_stateless_frontend_config["config"]["signing_key_path"]),
                             use="sig", alg="RS256")
        id_token_claims = JWS().verify_compact(resp_dict["id_token"], keys=[signing_key])

        assert all(
            (name, values) in id_token_claims.items()
            for name, values in OIDC_USERS[subject_id].items()
        )

    def test_full_stateless_code_flow(self, satosa_config_dict, oidc_stateless_frontend_config, saml_backend_config, idp_conf):
        subject_id = "testuser1"

        # proxy config
        satosa_config_dict["FRONTEND_MODULES"] = [oidc_stateless_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {attr_name: {"openid": [attr_name],
                                                                               "saml": [attr_name]}
                                                                   for attr_name in USERS[subject_id]}
        _, backend_metadata = create_entity_descriptors(SATOSAConfig(satosa_config_dict))

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), Response)

        # get frontend OP config info
        issuer = satosa_config_dict["BASE"]
        provider_config = self._discover_provider(test_client, issuer)

        # create auth req
        claims_request = ClaimsRequest(id_token=Claims(**{k: None for k in USERS[subject_id]}))
        req_args = {"scope": "openid", "response_type": "code", "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI, "nonce": "nonce",
                    "claims": claims_request.to_json()}
        auth_req = urlparse(provider_config["authorization_endpoint"]).path + "?" + urlencode(req_args)

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "303 See Other"

        # config test IdP
        backend_metadata_str = str(backend_metadata[saml_backend_config["name"]][0])
        idp_conf["metadata"]["inline"].append(backend_metadata_str)
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf))

        # create auth resp
        req_params = dict(parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query))
        url, authn_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            subject_id,
            response_binding=BINDING_HTTP_REDIRECT)

        # make auth resp to proxy
        authn_resp_req = urlparse(url).path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get(authn_resp_req)
        assert authn_resp.status == "303 See Other"

        resp_dict = dict(parse_qsl(urlparse(authn_resp.data.decode("utf-8")).query))
        code = resp_dict["code"]
        client_id_secret_str = CLIENT_ID + ":" + CLIENT_SECRET
        auth_header = "Basic %s" % base64.b64encode(client_id_secret_str.encode()).decode()

        authn_resp = test_client.post(provider_config["token_endpoint"],
                                      data={
                                          "code": code,
                                          "grant_type": "authorization_code",
                                          "redirect_uri": CLIENT_REDIRECT_URI
                                      },
                                      headers={'Authorization': auth_header})

        assert authn_resp.status == "200 OK"

        # verify auth resp from proxy
        resp_dict = json.loads(authn_resp.data.decode("utf-8"))
        signing_key = RSAKey(key=rsa_load(oidc_stateless_frontend_config["config"]["signing_key_path"]),
                             use="sig", alg="RS256")
        id_token_claims = JWS().verify_compact(resp_dict["id_token"], keys=[signing_key])

        assert all(
            (name, values) in id_token_claims.items()
            for name, values in OIDC_USERS[subject_id].items()
        )
