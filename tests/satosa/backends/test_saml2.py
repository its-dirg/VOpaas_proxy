"""
Tests for the SAML frontend module src/backends/saml2.py.
"""
import os
import re
from base64 import urlsafe_b64encode
from collections import Counter
from datetime import datetime
from unittest.mock import Mock, patch
from urllib.parse import urlparse, parse_qs, parse_qsl

import pytest

import saml2
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORD
from saml2.config import IdPConfig, SPConfig
from saml2.entity import Entity
from saml2.samlp import authn_request_from_string
from saml2.s_utils import deflate_and_base64_encode

from satosa.backends.saml2 import SAMLBackend
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.exception import SATOSAMissingStateError
from satosa.internal import InternalData
from tests.users import USERS
from tests.util import FakeIdP, create_metadata_from_config_dict, FakeSP

TEST_RESOURCE_BASE_PATH = os.path.join(os.path.dirname(__file__), "../../test_resources")

INTERNAL_ATTRIBUTES = {
    'attributes': {
        'displayname': {'saml': ['displayName']},
        'givenname': {'saml': ['givenName']},
        'mail': {'saml': ['email', 'emailAdress', 'mail']},
        'edupersontargetedid': {'saml': ['eduPersonTargetedID']},
        'name': {'saml': ['cn']},
        'surname': {'saml': ['sn', 'surname']}
    }
}

DISCOSRV_URL = "https://my.dicso.com/role/idp.ds"


def assert_redirect_to_discovery_server(
    redirect_response, sp_conf, expected_discosrv_url
):
    assert redirect_response.status == "303 See Other"
    parsed = urlparse(redirect_response.message)
    redirect_location = "{parsed.scheme}://{parsed.netloc}{parsed.path}".format(parsed=parsed)
    assert redirect_location == expected_discosrv_url

    request_params = dict(parse_qsl(parsed.query))
    assert request_params["return"] == sp_conf["service"]["sp"]["endpoints"]["discovery_response"][0][0]
    assert request_params["entityID"] == sp_conf["entityid"]


def assert_redirect_to_idp(redirect_response, idp_conf):
    assert redirect_response.status == "303 See Other"
    parsed = urlparse(redirect_response.message)
    redirect_location = "{parsed.scheme}://{parsed.netloc}{parsed.path}".format(parsed=parsed)
    assert redirect_location == idp_conf["service"]["idp"]["endpoints"]["single_sign_on_service"][0][0]
    assert "SAMLRequest" in parse_qs(parsed.query)


def assert_authn_response(internal_resp):
    assert internal_resp.auth_info.auth_class_ref == PASSWORD
    expected_data = {'surname': ['Testsson 1'], 'mail': ['test@example.com'],
                     'displayname': ['Test Testsson'], 'givenname': ['Test 1'],
                     'edupersontargetedid': ['one!for!all']}
    assert expected_data == internal_resp.attributes


def setup_test_config(sp_conf, idp_conf):
    idp_metadata_str = create_metadata_from_config_dict(idp_conf)
    sp_conf["metadata"]["inline"].append(idp_metadata_str)
    idp2_config = idp_conf.copy()
    idp2_config["entityid"] = "just_an_extra_idp"
    idp_metadata_str2 = create_metadata_from_config_dict(idp2_config)
    sp_conf["metadata"]["inline"].append(idp_metadata_str2)

    sp_metadata_str = create_metadata_from_config_dict(sp_conf)
    idp_conf["metadata"]["inline"] = [sp_metadata_str]


class TestSAMLBackend:
    @pytest.fixture(autouse=True)
    def create_backend(self, sp_conf, idp_conf):
        setup_test_config(sp_conf, idp_conf)
        self.samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                     "disco_srv": DISCOSRV_URL},
                                       "base_url",
                                       "samlbackend", None, None)

    def test_register_endpoints(self, sp_conf):
        """
        Tests the method register_endpoints
        """

        def get_path_from_url(url):
            return urlparse(url).path.lstrip("/")

        url_map = self.samlbackend.register_endpoints()
        all_sp_endpoints = [get_path_from_url(v[0][0]) for v in sp_conf["service"]["sp"]["endpoints"].values()]
        compiled_regex = [re.compile(regex) for regex, _ in url_map]
        for endp in all_sp_endpoints:
            assert any(p.match(endp) for p in compiled_regex)

    def test_start_auth_defaults_to_redirecting_to_discovery_server(self, context, sp_conf):
        resp = self.samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

    def test_discovery_server_set_in_context(self, context, sp_conf):
        discosrv_url = 'https://my.org/saml_discovery_service'
        context.decorate(
            SAMLBackend.KEY_SAML_DISCOVERY_SERVICE_URL, discosrv_url
        )
        resp = self.samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, discosrv_url)

    def test_full_flow(self, context, idp_conf, sp_conf):
        test_state_key = "test_state_key_456afgrh"
        response_binding = BINDING_HTTP_REDIRECT
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf))

        context.state[test_state_key] = "my_state"

        # start auth flow (redirecting to discovery server)
        resp = self.samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

        # fake response from discovery server
        disco_resp = parse_qs(urlparse(resp.message).query)
        info = parse_qs(urlparse(disco_resp["return"][0]).query)
        info["entityID"] = idp_conf["entityid"]
        request_context = Context()
        request_context.request = info
        request_context.state = context.state

        # pass discovery response to backend and check that it redirects to the selected IdP
        context.state["SATOSA_BASE"] = {"requester": "the-service-identifier"}
        resp = self.samlbackend.disco_response(request_context)
        assert_redirect_to_idp(resp, idp_conf)

        # fake auth response to the auth request
        req_params = dict(parse_qsl(urlparse(resp.message).query))
        url, fake_idp_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            "testuser1",
            response_binding=response_binding)
        response_context = Context()
        response_context.request = fake_idp_resp
        response_context.state = request_context.state

        # pass auth response to backend and verify behavior
        self.samlbackend.authn_response(response_context, response_binding)
        context, internal_resp = self.samlbackend.auth_callback_func.call_args[0]
        assert context.state[test_state_key] == "my_state"
        assert_authn_response(internal_resp)

    def test_start_auth_redirects_directly_to_mirrored_idp(
            self, context, idp_conf):
        entityid = idp_conf["entityid"]
        context.decorate(Context.KEY_TARGET_ENTITYID, entityid)

        resp = self.samlbackend.start_auth(context, InternalData())
        assert_redirect_to_idp(resp, idp_conf)

    def test_redirect_to_idp_if_only_one_idp_in_metadata(self, context, sp_conf, idp_conf):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, without any discovery service configured
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf}, "base_url", "saml_backend", None,
                                  None)

        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_idp(resp, idp_conf)

    def test_authn_request(self, context, idp_conf):
        resp = self.samlbackend.authn_request(context, idp_conf["entityid"])
        assert_redirect_to_idp(resp, idp_conf)
        req_params = dict(parse_qsl(urlparse(resp.message).query))
        assert context.state[self.samlbackend.name]["relay_state"] == req_params["RelayState"]

    @pytest.mark.parametrize("hostname", ["example.com:8443", "example.net"])
    @pytest.mark.parametrize(
        "strat",
        ["", "use_first_acs", "prefer_matching_host", "invalid"],
    )
    def test_acs_selection_strategy(self, context, sp_conf, idp_conf, hostname, strat):
        acs_endpoints = [
            ("https://example.com/saml2/acs/post", BINDING_HTTP_POST),
            ("https://example.net/saml2/acs/post", BINDING_HTTP_POST),
            ("https://example.com:8443/saml2/acs/post", BINDING_HTTP_POST),
        ]
        config = {"sp_config": sp_conf}
        config["sp_config"]["service"]["sp"]["endpoints"][
            "assertion_consumer_service"
        ] = acs_endpoints
        if strat:
            config["acs_selection_strategy"] = strat

        req = self._make_authn_request(hostname, context, config, idp_conf["entityid"])

        if strat == "prefer_matching_host":
            expected_acs = hostname
        else:
            expected_acs = urlparse(acs_endpoints[0][0]).netloc
        assert urlparse(req.assertion_consumer_service_url).netloc == expected_acs

    def _make_authn_request(self, http_host, context, config, entity_id):
        context.http_headers = {"HTTP_HOST": http_host} if http_host else {}
        self.samlbackend = SAMLBackend(
            Mock(),
            INTERNAL_ATTRIBUTES,
            config,
            "base_url",
            "samlbackend",
            None,
            None
        )
        resp = self.samlbackend.authn_request(context, entity_id)
        req_params = dict(parse_qsl(urlparse(resp.message).query))
        req_xml = Entity.unravel(req_params["SAMLRequest"], BINDING_HTTP_REDIRECT)
        return authn_request_from_string(req_xml)

    @pytest.mark.parametrize("hostname", ["unknown-hostname", None])
    def test_unknown_or_no_hostname_selects_first_acs(
        self, context, sp_conf, idp_conf, hostname
    ):
        config = {"sp_config": sp_conf}
        config["sp_config"]["service"]["sp"]["endpoints"][
            "assertion_consumer_service"
        ] = (
            ("https://first-hostname/saml2/acs/post", BINDING_HTTP_POST),
            ("https://other-hostname/saml2/acs/post", BINDING_HTTP_POST),
        )
        config["acs_selection_strategy"] = "prefer_matching_host"
        req = self._make_authn_request(hostname, context, config, idp_conf["entityid"])
        assert (
            req.assertion_consumer_service_url
            == "https://first-hostname/saml2/acs/post"
        )

    def test_authn_response(self, context, idp_conf, sp_conf):
        response_binding = BINDING_HTTP_REDIRECT
        request_params, auth_resp = self._perform_request_response(
            idp_conf, sp_conf, response_binding
        )
        context.request = auth_resp
        context.state[self.samlbackend.name] = {"relay_state": request_params["RelayState"]}
        self.samlbackend.authn_response(context, response_binding)

        context, internal_resp = self.samlbackend.auth_callback_func.call_args[0]
        assert_authn_response(internal_resp)

    def _perform_request_response(
        self, idp_conf, sp_conf, response_binding, receive_nameid=True
    ):
        fakesp = FakeSP(SPConfig().load(sp_conf))
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf))
        destination, request_params = fakesp.make_auth_req(idp_conf["entityid"])
        auth_resp_func = (
            fakeidp.handle_auth_req
            if receive_nameid
            else fakeidp.handle_auth_req_no_name_id
        )
        url, auth_resp = auth_resp_func(
            request_params["SAMLRequest"],
            request_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            "testuser1",
            response_binding=response_binding,
        )

        return request_params, auth_resp

    def test_no_state_raises_error(self, context, idp_conf, sp_conf):
        response_binding = BINDING_HTTP_REDIRECT
        request_params, auth_resp = self._perform_request_response(
            idp_conf, sp_conf, response_binding
        )
        context.request = auth_resp
        # not setting context.state[self.samlbackend.name]
        # to simulate a request with lost state

        with pytest.raises(SATOSAMissingStateError):
            self.samlbackend.authn_response(context, response_binding)

    def test_no_relay_state_raises_error(self, context, idp_conf, sp_conf):
        response_binding = BINDING_HTTP_REDIRECT
        request_params, auth_resp = self._perform_request_response(
            idp_conf, sp_conf, response_binding
        )
        context.request = auth_resp
        # not setting context.state[self.samlbackend.name]["relay_state"]
        # to simulate a request without a relay state
        context.state[self.samlbackend.name] = {}

        with pytest.raises(SATOSAAuthenticationError):
            self.samlbackend.authn_response(context, response_binding)

    @pytest.mark.skipif(
        saml2.__version__ < '4.6.1',
        reason="Optional NameID needs pysaml2 v4.6.1 or higher"
    )
    def test_authn_response_no_name_id(self, context, idp_conf, sp_conf):
        response_binding = BINDING_HTTP_REDIRECT

        request_params, auth_resp = self._perform_request_response(
            idp_conf, sp_conf, response_binding, receive_nameid=False
        )

        backend = self.samlbackend

        context.request = auth_resp
        context.state[backend.name] = {
            "relay_state": request_params["RelayState"],
        }
        backend.authn_response(context, response_binding)

        context, internal_resp = backend.auth_callback_func.call_args[0]
        assert_authn_response(internal_resp)

    def test_authn_response_with_encrypted_assertion(self, sp_conf, context):
        with open(os.path.join(
            TEST_RESOURCE_BASE_PATH,
            "idp_metadata_for_encrypted_signed_auth_response.xml"
        )) as idp_metadata_file:
            sp_conf["metadata"]["inline"] = [idp_metadata_file.read()]

        sp_conf["entityid"] = "https://federation-dev-1.scienceforum.sc/Saml2/proxy_saml2_backend.xml"
        samlbackend = SAMLBackend(
            Mock(),
            INTERNAL_ATTRIBUTES,
            {"sp_config": sp_conf, "disco_srv": DISCOSRV_URL},
            "base_url",
            "samlbackend",
            None,
            None
        )
        response_binding = BINDING_HTTP_REDIRECT
        relay_state = "test relay state"

        with open(os.path.join(
            TEST_RESOURCE_BASE_PATH,
            "auth_response_with_encrypted_signed_assertion.xml"
        )) as auth_response_file:
            auth_response = auth_response_file.read()

        context.request = {"SAMLResponse": deflate_and_base64_encode(auth_response), "RelayState": relay_state}

        context.state[self.samlbackend.name] = {"relay_state": relay_state}
        with open(
            os.path.join(TEST_RESOURCE_BASE_PATH, "encryption_key.pem")
        ) as encryption_key_file:
            samlbackend.encryption_keys = [encryption_key_file.read()]

        assertion_issued_at = 1479315212
        with patch('saml2.validate.time_util.shift_time') as mock_shift_time, \
                patch('saml2.validate.time_util.utc_now') as mock_utc_now:
            mock_utc_now.return_value = assertion_issued_at + 1
            mock_shift_time.side_effect = [
                datetime.utcfromtimestamp(assertion_issued_at + 1),
                datetime.utcfromtimestamp(assertion_issued_at - 1),
            ]
            samlbackend.authn_response(context, response_binding)

        context, internal_resp = samlbackend.auth_callback_func.call_args[0]
        assert Counter(internal_resp.attributes.keys()) == Counter({"mail", "givenname", "displayname", "surname"})

    def test_backend_reads_encryption_key_from_key_file(self, sp_conf):
        sp_conf["key_file"] = os.path.join(TEST_RESOURCE_BASE_PATH, "encryption_key.pem")
        samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                "disco_srv": DISCOSRV_URL},
                                  "base_url", "samlbackend", None, None)
        assert samlbackend.encryption_keys

    def test_backend_reads_encryption_key_from_encryption_keypair(self, sp_conf):
        del sp_conf["key_file"]
        sp_conf["encryption_keypairs"] = [{"key_file": os.path.join(TEST_RESOURCE_BASE_PATH, "encryption_key.pem")}]
        samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                "disco_srv": DISCOSRV_URL},
                                  "base_url", "samlbackend", None, None)
        assert samlbackend.encryption_keys

    def test_metadata_endpoint(self, context, sp_conf):
        resp = self.samlbackend._metadata_endpoint(context)
        headers = dict(resp.headers)
        assert headers["Content-Type"] == "text/xml"
        assert sp_conf["entityid"] in resp.message

    def test_get_metadata_desc(self, sp_conf, idp_conf):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, with a single backing IdP
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf}, "base_url", "saml_backend", None,
                                  None)
        entity_descriptions = samlbackend.get_metadata_desc()

        assert len(entity_descriptions) == 1

        idp_desc = entity_descriptions[0].to_dict()

        assert idp_desc["entityid"] == urlsafe_b64encode(idp_conf["entityid"].encode("utf-8")).decode("utf-8")
        assert idp_desc["contact_person"] == idp_conf["contact_person"]

        assert idp_desc["organization"]["name"][0] == tuple(idp_conf["organization"]["name"][0])
        assert idp_desc["organization"]["display_name"][0] == tuple(idp_conf["organization"]["display_name"][0])
        assert idp_desc["organization"]["url"][0] == tuple(idp_conf["organization"]["url"][0])

        expected_ui_info = idp_conf["service"]["idp"]["ui_info"]
        ui_info = idp_desc["service"]["idp"]["ui_info"]
        assert ui_info["display_name"] == expected_ui_info["display_name"]
        assert ui_info["description"] == expected_ui_info["description"]
        assert ui_info["logo"] == expected_ui_info["logo"]

    def test_get_metadata_desc_with_logo_without_lang(self, sp_conf, idp_conf):
        # add logo without 'lang'
        idp_conf["service"]["idp"]["ui_info"]["logo"] = [{"text": "https://idp.example.com/static/logo.png",
                                                          "width": "120", "height": "60"}]

        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, with a single backing IdP
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf}, "base_url", "saml_backend", None,
                                  None)
        entity_descriptions = samlbackend.get_metadata_desc()

        assert len(entity_descriptions) == 1

        idp_desc = entity_descriptions[0].to_dict()

        assert idp_desc["entityid"] == urlsafe_b64encode(idp_conf["entityid"].encode("utf-8")).decode("utf-8")
        assert idp_desc["contact_person"] == idp_conf["contact_person"]

        assert idp_desc["organization"]["name"][0] == tuple(idp_conf["organization"]["name"][0])
        assert idp_desc["organization"]["display_name"][0] == tuple(idp_conf["organization"]["display_name"][0])
        assert idp_desc["organization"]["url"][0] == tuple(idp_conf["organization"]["url"][0])

        expected_ui_info = idp_conf["service"]["idp"]["ui_info"]
        ui_info = idp_desc["service"]["idp"]["ui_info"]
        assert ui_info["display_name"] == expected_ui_info["display_name"]
        assert ui_info["description"] == expected_ui_info["description"]
        assert ui_info["logo"] == expected_ui_info["logo"]


class TestSAMLBackendRedirects:
    def test_default_redirect_to_discovery_service_if_using_mdq(
        self, context, sp_conf, idp_conf
    ):
        # one IdP in the metadata, but MDQ also configured so should always redirect to the discovery service
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        sp_conf["metadata"]["mdq"] = ["https://mdq.example.com"]
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf, "disco_srv": DISCOSRV_URL,},
                                  "base_url", "saml_backend", None, None)
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

    def test_use_of_disco_or_redirect_to_idp_when_using_mdq_and_forceauthn_is_not_set(
        self, context, sp_conf, idp_conf
    ):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        sp_conf["metadata"]["mdq"] = ["https://mdq.example.com"]

        backend_conf = {
            SAMLBackend.KEY_SP_CONFIG: sp_conf,
            SAMLBackend.KEY_DISCO_SRV: DISCOSRV_URL,
            SAMLBackend.KEY_MEMORIZE_IDP: True,
        }
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

        context.state[Context.KEY_MEMORIZED_IDP] = idp_conf["entityid"]
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_idp(resp, idp_conf)

        backend_conf[SAMLBackend.KEY_MEMORIZE_IDP] = False
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

        context.decorate(Context.KEY_FORCE_AUTHN, "0")
        context.state[Context.KEY_MEMORIZED_IDP] = idp_conf["entityid"]
        backend_conf[SAMLBackend.KEY_USE_MEMORIZED_IDP_WHEN_FORCE_AUTHN] = True
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

    def test_use_of_disco_or_redirect_to_idp_when_using_mdq_and_forceauthn_is_set_true(
        self, context, sp_conf, idp_conf
    ):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        sp_conf["metadata"]["mdq"] = ["https://mdq.example.com"]

        context.decorate(Context.KEY_FORCE_AUTHN, "true")
        context.state[Context.KEY_MEMORIZED_IDP] = idp_conf["entityid"]

        backend_conf = {
            SAMLBackend.KEY_SP_CONFIG: sp_conf,
            SAMLBackend.KEY_DISCO_SRV: DISCOSRV_URL,
            SAMLBackend.KEY_MEMORIZE_IDP: True,
            SAMLBackend.KEY_MIRROR_FORCE_AUTHN: True,
        }
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

        backend_conf[SAMLBackend.KEY_USE_MEMORIZED_IDP_WHEN_FORCE_AUTHN] = True
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_idp(resp, idp_conf)

    def test_use_of_disco_or_redirect_to_idp_when_using_mdq_and_forceauthn_is_set_1(
        self, context, sp_conf, idp_conf
    ):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        sp_conf["metadata"]["mdq"] = ["https://mdq.example.com"]

        context.decorate(Context.KEY_FORCE_AUTHN, "1")
        context.state[Context.KEY_MEMORIZED_IDP] = idp_conf["entityid"]

        backend_conf = {
            SAMLBackend.KEY_SP_CONFIG: sp_conf,
            SAMLBackend.KEY_DISCO_SRV: DISCOSRV_URL,
            SAMLBackend.KEY_MEMORIZE_IDP: True,
            SAMLBackend.KEY_MIRROR_FORCE_AUTHN: True,
        }
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_discovery_server(resp, sp_conf, DISCOSRV_URL)

        backend_conf[SAMLBackend.KEY_USE_MEMORIZED_IDP_WHEN_FORCE_AUTHN] = True
        samlbackend = SAMLBackend(
            None, INTERNAL_ATTRIBUTES, backend_conf, "base_url", "saml_backend", None, None
        )
        resp = samlbackend.start_auth(context, InternalData())
        assert_redirect_to_idp(resp, idp_conf)
