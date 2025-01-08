"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import copy
import itertools
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

import pytest
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORD
from saml2.config import SPConfig
from saml2.entity_category import refeds, swamid, edugain
from saml2.entity_category.edugain import COCO
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.entity_category.swamid import SFS_1993_1153, RESEARCH_AND_EDUCATION, EU, HEI, NREN
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.saml import NameID, Subject
from saml2.samlp import NameIDPolicy

from satosa.attribute_mapping import AttributeMapper
from satosa.frontends.saml2 import SAMLFrontend, SAMLMirrorFrontend
from satosa.frontends.saml2 import SAMLVirtualCoFrontend
from satosa.frontends.saml2 import subject_type_to_saml_nameid_format
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.state import State
from tests.users import USERS
from tests.util import FakeSP, create_metadata_from_config_dict

INTERNAL_ATTRIBUTES = {
    "attributes": {
        "displayname": {"saml": ["displayName"]},
        "givenname": {"saml": ["givenName"]},
        "mail": {"saml": ["email", "emailAdress", "mail"]},
        "edupersontargetedid": {"saml": ["eduPersonTargetedID"]},
        "name": {"saml": ["cn"]},
        "surname": {"saml": ["sn", "surname"]}
    }
}

ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"},
             "single_logout_service": {BINDING_HTTP_REDIRECT: "slo/redirect",
                                       BINDING_HTTP_POST: "slo/post"}}
BASE_URL = "https://satosa-idp.example.com"


class TestSAMLFrontend:
    @pytest.fixture
    def internal_response(self, idp_conf):
        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", idp_conf["entityid"])
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(INTERNAL_ATTRIBUTES).to_internal("saml", USERS["testuser1"])
        return internal_response

    def construct_base_url_from_entity_id(self, entity_id):
        return "{parsed.scheme}://{parsed.netloc}".format(parsed=urlparse(entity_id))

    def setup_for_authn_req(self, context, idp_conf, sp_conf, nameid_format=None, relay_state="relay_state",
                            internal_attributes=INTERNAL_ATTRIBUTES, extra_config={},
                            subject=None):
        config = {"idp_config": idp_conf, "endpoints": ENDPOINTS}
        config.update(extra_config)
        sp_metadata_str = create_metadata_from_config_dict(sp_conf)
        idp_conf["metadata"]["inline"] = [sp_metadata_str]

        base_url = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        samlfrontend = SAMLFrontend(lambda ctx, internal_req: (ctx, internal_req),
                                    internal_attributes, config, base_url, "saml_frontend",
                                    lambda ctx, internal_logout_req: (ctx, internal_logout_req))
        samlfrontend.register_endpoints(["saml"])

        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)

        fakesp = FakeSP(SPConfig().load(sp_conf))
        destination, auth_req = fakesp.make_auth_req(
            samlfrontend.idp_config["entityid"],
            nameid_format,
            relay_state,
            subject=subject,
        )
        context.request = auth_req
        tmp_dict = {}
        for val in context.request:
            if isinstance(context.request[val], list):
                tmp_dict[val] = context.request[val][0]
            else:
                tmp_dict[val] = context.request[val]
        context.request = tmp_dict

        return samlfrontend

    def get_auth_response(self, samlfrontend, context, internal_response, sp_conf, idp_metadata_str):
        sp_config = SPConfig().load(sp_conf)
        resp_args = {
            "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT),
            "in_response_to": None,
            "destination": sp_config.endpoint("assertion_consumer_service", binding=BINDING_HTTP_REDIRECT)[0],
            "sp_entity_id": sp_conf["entityid"],
            "binding": BINDING_HTTP_REDIRECT
        }
        request_state = samlfrontend._create_state_data(context, resp_args, "")
        context.state[samlfrontend.name] = request_state

        resp = samlfrontend.handle_authn_response(context, internal_response)

        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        fakesp = FakeSP(sp_config)
        resp_dict = parse_qs(urlparse(resp.message).query)
        return fakesp.parse_authn_request_response(resp_dict["SAMLResponse"][0], BINDING_HTTP_REDIRECT)

    @pytest.mark.parametrize("conf", [
        None,
        {"idp_config_notok": {}, "endpoints": {}},
        {"idp_config": {}, "endpoints_notok": {}}
    ])
    def test_config_error_handling(self, conf):
        with pytest.raises(ValueError):
            SAMLFrontend(lambda ctx, req: None,
                         INTERNAL_ATTRIBUTES, conf, "base_url", "saml_frontend",
                         lambda ctx, req: None)

    def test_register_endpoints(self, idp_conf):
        """
        Tests the method register_endpoints
        """

        def get_path_from_url(url):
            return urlparse(url).path.lstrip("/")

        config = {"idp_config": idp_conf, "endpoints": ENDPOINTS}

        base_url = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        samlfrontend = SAMLFrontend(lambda context, internal_req: (context, internal_req),
                                    INTERNAL_ATTRIBUTES, config, base_url, "saml_frontend",
                                    lambda context, internal_logout_req: (context, internal_logout_req))

        providers = ["foo", "bar"]
        url_map = samlfrontend.register_endpoints(providers)
        all_idp_endpoints = [get_path_from_url(v[0][0]) for v in idp_conf["service"]["idp"]["endpoints"].values()]
        compiled_regex = [re.compile(regex) for regex, _ in url_map]
        for endp in all_idp_endpoints:
            assert any(p.match(endp) for p in compiled_regex)

    def test_handle_authn_request(self, context, idp_conf, sp_conf, internal_response):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requester == sp_conf["entityid"]

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(SPConfig().load(sp_conf))
        resp = fakesp.parse_authn_request_response(resp_dict["SAMLResponse"][0],
                                                   BINDING_HTTP_REDIRECT)
        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

    def test_create_authn_request_with_subject(self, context, idp_conf, sp_conf, internal_response):
        name_id_value = 'somenameid'
        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=name_id_value)
        subject = Subject(name_id=name_id)
        samlfrontend = self.setup_for_authn_req(
            context, idp_conf, sp_conf, subject=subject
        )
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.subject_id == name_id_value
        # XXX TODO how should type be handled?
        # assert internal_req.subject_type == NAMEID_FORMAT_UNSPECIFIED

    def test_handle_authn_request_without_name_id_policy_default_to_name_id_format_from_metadata(
            self, context, idp_conf, sp_conf):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, nameid_format="")
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.subject_type == sp_conf["service"]["sp"]["name_id_format"][0]

    def test_handle_authn_request_without_name_id_policy_and_metadata_without_name_id_format(
            self, context, idp_conf, sp_conf):
        del sp_conf["service"]["sp"]["name_id_format"]
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, nameid_format="")
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.subject_type == NAMEID_FORMAT_TRANSIENT

    def test_handle_authn_response_without_relay_state(self, context, idp_conf, sp_conf, internal_response):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, relay_state=None)
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requester == sp_conf["entityid"]

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(SPConfig().load(sp_conf))
        resp = fakesp.parse_authn_request_response(resp_dict["SAMLResponse"][0],
                                                   BINDING_HTTP_REDIRECT)

        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

        assert samlfrontend.name not in context.state

    def test_handle_authn_response_without_name_id(
                          self, context, idp_conf, sp_conf, internal_response):
        samlfrontend = self.setup_for_authn_req(
                                  context, idp_conf, sp_conf, relay_state=None)
        _, internal_req = samlfrontend.handle_authn_request(
                                                context, BINDING_HTTP_REDIRECT)

        # Make sure we are testing the equivalent of a <Response> with no
        # <NameID> in the <Subject>.
        assert internal_response.subject_type is None
        assert internal_response.subject_id is None

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(SPConfig().load(sp_conf))
        resp = fakesp.parse_authn_request_response(
                           resp_dict["SAMLResponse"][0], BINDING_HTTP_REDIRECT)

        # The <NameID> must not have an empty TextContent.
        assert resp.name_id.text is not None

    def test_get_filter_attributes_with_sp_requested_attributes_without_friendlyname(self, idp_conf):
        sp_metadata_str = """<?xml version="1.0"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://sp.example.com">
          <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AttributeConsumingService>
              <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
              <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
              <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
              <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
              <md:RequestedAttribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
              <md:RequestedAttribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
              <md:RequestedAttribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
            </md:AttributeConsumingService>
          </md:SPSSODescriptor>
        </md:EntityDescriptor>
        """

        idp_conf["metadata"] = {"inline": [sp_metadata_str]}

        base_url = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS}

        internal_attributes = {"attributes": {attr_name.lower(): {"saml": [attr_name]} for attr_name in
                                              ["eduPersonTargetedID", "eduPersonPrincipalName",
                                               "eduPersonAffiliation", "mail", "displayName", "sn",
                                               "givenName"]}}  # no op mapping for saml attribute names

        samlfrontend = SAMLFrontend(None, internal_attributes, conf, base_url, "saml_frontend", None)
        samlfrontend.register_endpoints(["testprovider"])

        internal_req = InternalData(
            subject_type=NAMEID_FORMAT_PERSISTENT,
            requester="http://sp.example.com",
            requester_name="Example SP",
        )
        filtered_attributes = samlfrontend._get_approved_attributes(samlfrontend.idp,
                                                                    samlfrontend.idp.config.getattr(
                                                                        "policy", "idp"),
                                                                    internal_req.requester, None)

        assert set(filtered_attributes) == set(["edupersontargetedid", "edupersonprincipalname",
                                                "edupersonaffiliation", "mail", "displayname", "sn", "givenname"])

    def test_acr_mapping_in_authn_response(self, context, idp_conf, sp_conf, internal_response):
        eidas_loa_low = "http://eidas.europa.eu/LoA/low"
        loa = {"": eidas_loa_low}
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, extra_config={"acr_mapping": loa})
        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert len(resp.assertion.authn_statement) == 1
        authn_context_class_ref = resp.assertion.authn_statement[0].authn_context.authn_context_class_ref
        assert authn_context_class_ref.text == eidas_loa_low

    def test_acr_mapping_per_idp_in_authn_response(self, context, idp_conf, sp_conf, internal_response):
        expected_loa = "LoA1"
        loa = {"": "http://eidas.europa.eu/LoA/low", idp_conf["entityid"]: expected_loa}
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, extra_config={"acr_mapping": loa})
        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert len(resp.assertion.authn_statement) == 1
        authn_context_class_ref = resp.assertion.authn_statement[0].authn_context.authn_context_class_ref
        assert authn_context_class_ref.text == expected_loa

    @pytest.mark.parametrize(
        "entity_category, entity_category_module, expected_attributes",
        [
            ([""], "swamid", swamid.RELEASE[""]),
            ([COCO], "edugain", edugain.RELEASE[""] + edugain.RELEASE[COCO]),
            ([RESEARCH_AND_SCHOLARSHIP], "refeds", refeds.RELEASE[""] + refeds.RELEASE[RESEARCH_AND_SCHOLARSHIP]),
            ([RESEARCH_AND_EDUCATION, EU], "swamid", swamid.RELEASE[""] + swamid.RELEASE[(RESEARCH_AND_EDUCATION, EU)]),
            ([RESEARCH_AND_EDUCATION, HEI], "swamid", swamid.RELEASE[""] + swamid.RELEASE[(RESEARCH_AND_EDUCATION, HEI)]),
            ([RESEARCH_AND_EDUCATION, NREN], "swamid", swamid.RELEASE[""] + swamid.RELEASE[(RESEARCH_AND_EDUCATION, NREN)]),
            ([SFS_1993_1153], "swamid", swamid.RELEASE[""] + swamid.RELEASE[SFS_1993_1153]),
        ]
    )
    def test_respect_sp_entity_categories(
        self,
        context,
        entity_category,
        entity_category_module,
        expected_attributes,
        idp_conf,
        sp_conf,
        internal_response
    ):
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        idp_conf["service"]["idp"]["policy"]["default"]["entity_categories"] = [entity_category_module]
        if all(entity_category):  # don't insert empty entity category
            sp_conf["entity_category"] = entity_category
        if entity_category == [COCO]:
            sp_conf["service"]["sp"]["required_attributes"] = expected_attributes

        expected_attributes_in_all_entity_categories = set(
            itertools.chain(
                swamid.RELEASE[""],
                edugain.RELEASE[""],
                edugain.RELEASE[COCO],
                refeds.RELEASE[RESEARCH_AND_SCHOLARSHIP],
                swamid.RELEASE[(RESEARCH_AND_EDUCATION, EU)],
                swamid.RELEASE[(RESEARCH_AND_EDUCATION, HEI)],
                swamid.RELEASE[(RESEARCH_AND_EDUCATION, NREN)],
                swamid.RELEASE[SFS_1993_1153],
            )
        )
        attribute_mapping = {}
        for expected_attribute in expected_attributes_in_all_entity_categories:
            attribute_mapping[expected_attribute.lower()] = {"saml": [expected_attribute]}

        internal_attributes = dict(attributes=attribute_mapping)
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, internal_attributes=internal_attributes)

        user_attributes = {k: "foo" for k in expected_attributes_in_all_entity_categories}
        internal_response.attributes = AttributeMapper(internal_attributes).to_internal("saml", user_attributes)
        internal_response.requester = sp_conf["entityid"]

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert Counter(resp.ava.keys()) == Counter(expected_attributes)

    def test_sp_metadata_including_uiinfo_display_name(self, context, idp_conf, sp_conf):
        sp_conf["service"]["sp"]["ui_info"] = dict(display_name="Test SP")
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        display_names = samlfrontend._get_sp_display_name(samlfrontend.idp, sp_conf["entityid"])
        assert display_names[0]["text"] == "Test SP"

    def test_sp_metadata_including_uiinfo_without_display_name(self, context, idp_conf, sp_conf):
        sp_conf["service"]["sp"]["ui_info"] = dict(information_url="http://info.example.com")
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        assert samlfrontend._get_sp_display_name(samlfrontend.idp, sp_conf["entityid"]) is None

    def test_sp_metadata_without_uiinfo(self, context, idp_conf, sp_conf):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        assert samlfrontend._get_sp_display_name(samlfrontend.idp, sp_conf["entityid"]) is None

    def test_metadata_endpoint(self, context, idp_conf):
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS}
        samlfrontend = SAMLFrontend(lambda ctx, req: None,
                                    INTERNAL_ATTRIBUTES, conf, "base_url", "saml_frontend",
                                    lambda ctx, req: None)
        samlfrontend.register_endpoints(["todo"])
        resp = samlfrontend._metadata_endpoint(context)
        headers = dict(resp.headers)
        assert headers["Content-Type"] == "text/xml"
        assert idp_conf["entityid"] in resp.message

    def test_custom_attribute_release_with_less_attributes_than_entity_category(
        self, context, idp_conf, sp_conf, internal_response
    ):
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        idp_conf["service"]["idp"]["policy"]["default"]["entity_categories"] = ["swamid"]
        sp_conf["entity_category"] = [SFS_1993_1153]
        expected_attributes = swamid.RELEASE[SFS_1993_1153]

        attribute_mapping = {}
        for expected_attribute in expected_attributes:
            attribute_mapping[expected_attribute.lower()] = {"saml": [expected_attribute]}
        internal_attributes = dict(attributes=attribute_mapping)

        user_attributes = {k: "foo" for k in expected_attributes}
        internal_response.attributes = AttributeMapper(internal_attributes).to_internal("saml", user_attributes)

        custom_attributes = {idp_conf["entityid"]: {sp_conf["entityid"]: {"exclude": ["norEduPersonNIN"]}}}
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, internal_attributes=internal_attributes,
                                                extra_config=dict(custom_attribute_release=custom_attributes))

        internal_response.requester = sp_conf["entityid"]
        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert len(resp.ava.keys()) == (
            len(expected_attributes)
            - len(custom_attributes[internal_response.auth_info.issuer][internal_response.requester]["exclude"])
        )


class TestSAMLMirrorFrontend:
    BACKEND = "test_backend"
    TARGET_ENTITY_ID = "target-idp.entity_id"

    @pytest.fixture(autouse=True)
    def create_frontend(self, idp_conf):
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS}
        self.frontend = SAMLMirrorFrontend(lambda ctx, req: None,
                                           INTERNAL_ATTRIBUTES, conf, BASE_URL,
                                           "saml_mirror_frontend",
                                           lambda ctx, req: None)
        self.frontend.register_endpoints([self.BACKEND])

    def assert_dynamic_endpoints(self, sso_endpoints):
        endpoint_base_url = "{}/{}/{}".format(BASE_URL, self.BACKEND, self.TARGET_ENTITY_ID)
        expected_endpoints = []
        for binding, endpoint in ENDPOINTS["single_sign_on_service"].items():
            endp = "{}/{}".format(endpoint_base_url, endpoint)
            expected_endpoints.append((endp, binding))

        assert all(sso in sso_endpoints for sso in expected_endpoints)

    def test_load_endpoints_to_config(self):
        idp_config = self.frontend._load_endpoints_to_config(self.BACKEND, self.TARGET_ENTITY_ID)
        self.assert_dynamic_endpoints(idp_config["service"]["idp"]["endpoints"]["single_sign_on_service"])

    def test_load_idp_dynamic_endpoints(self, context):
        context.path = "{}/{}/sso/redirect".format(self.BACKEND, self.TARGET_ENTITY_ID)
        context.target_backend = self.BACKEND
        idp = self.frontend._load_idp_dynamic_endpoints(context)
        self.assert_dynamic_endpoints(idp.config._idp_endpoints["single_sign_on_service"])

    def test_load_idp_dynamic_entity_id(self, idp_conf):
        state = State()
        state[self.frontend.name] = {"target_entity_id": self.TARGET_ENTITY_ID}
        idp = self.frontend._load_idp_dynamic_entity_id(state)
        assert idp.config.entityid == "{}/{}".format(idp_conf["entityid"], self.TARGET_ENTITY_ID)


class TestSAMLVirtualCoFrontend(TestSAMLFrontend):
    BACKEND = "test_backend"
    BACKEND_1 = "test_backend_1"
    CO = "MESS"
    CO_O = "organization"
    CO_C = "countryname"
    CO_CO = "friendlycountryname"
    CO_NOREDUORGACRONYM = "noreduorgacronym"
    CO_SCOPE = "messproject.org"
    CO_STATIC_SAML_ATTRIBUTES = {
        CO_O: ["Medium Energy Synchrotron Source"],
        CO_C: ["US"],
        CO_CO: ["United States"],
        CO_NOREDUORGACRONYM: ["MESS"],
    }
    KEY_SSO = "single_sign_on_service"

    @pytest.fixture
    def frontend(self, idp_conf, sp_conf):
        """
        This fixture is an instance of the SAMLVirtualCoFrontend with an IdP
        configuration that includes SAML metadata for the test SP configured
        by the sp_conf fixture so that we can test a SAML Response sent
        from the IdP.
        """
        # Use a utility function to serialize the sp_conf fixture as
        # a string and then dynamically add it as the metadata available
        # as part of the idp_conf fixture.
        sp_metadata_str = create_metadata_from_config_dict(sp_conf)
        idp_conf["metadata"]["inline"] = [sp_metadata_str]

        # Dynamically add configuration details for the CO including static
        # SAML attributes so their presence in a SAML Response can be tested.
        collab_org = {
            "encodeable_name": self.CO,
            "co_static_saml_attributes": self.CO_STATIC_SAML_ATTRIBUTES,
            "co_attribute_scope": self.CO_SCOPE
        }

        # Use the dynamically updated idp_conf fixture, the configured
        # endpoints, and the collaborative organization configuration to
        # create the configuration for the frontend.
        conf = {
            "idp_config": idp_conf,
            "endpoints": ENDPOINTS,
            "collaborative_organizations": [collab_org],
        }

        # Use a richer set of internal attributes than what is provided
        # for the parent class so that we can test for the static SAML
        # attributes about the CO being asserted.
        internal_attributes = INTERNAL_ATTRIBUTES
        internal_attributes["attributes"][self.CO_O] = {"saml": ["o"]}
        internal_attributes["attributes"][self.CO_C] = {"saml": ["c"]}
        internal_attributes["attributes"][self.CO_CO] = {"saml": ["co"]}
        internal_attributes["attributes"][self.CO_NOREDUORGACRONYM] = (
            {"saml": ["norEduOrgAcronym"]})

        # Create, register the endpoints, and then return the frontend
        # instance.
        frontend = SAMLVirtualCoFrontend(lambda ctx, req: None,
                                         internal_attributes,
                                         conf,
                                         BASE_URL,
                                         "saml_virtual_co_frontend",
                                        )
        frontend.register_endpoints([self.BACKEND])

        return frontend

    @pytest.fixture
    def context(self, context):
        """
        This fixture is an instance of the context that mocks up the context
        that would be available during a SAML flow and that would include
        a path and target_backend that indicates the CO.
        """
        return self._make_context(context, self.BACKEND, self.CO)

    def _make_context(self, context, backend, co_name):
        _context = copy.deepcopy(context)
        _context.path = "{}/{}/sso/redirect".format(backend, co_name)
        _context.target_backend = backend
        return _context

    def test_create_state_data(self, frontend, context, idp_conf):
        frontend._create_co_virtual_idp(context)
        state = frontend._create_state_data(context, {}, "")
        assert state[frontend.KEY_CO_NAME] == self.CO

        expected_entityid = "{}/{}".format(idp_conf['entityid'], self.CO)
        assert state[frontend.KEY_CO_ENTITY_ID] == expected_entityid

        assert state[frontend.KEY_CO_ATTRIBUTE_SCOPE] == self.CO_SCOPE

    def test_get_co_name(self, frontend, context):
        co_name = frontend._get_co_name(context)
        assert co_name == self.CO

        frontend._create_state_data(context, {}, "")
        co_name = frontend._get_co_name(context)
        assert co_name == self.CO

    def test_create_co_virtual_idp(self, frontend, context, idp_conf):
        expected_entityid = "{}/{}".format(idp_conf['entityid'], self.CO)

        endpoint_base_url = "{}/{}/{}".format(BASE_URL, self.BACKEND, self.CO)
        expected_endpoints = []
        for binding, endpoint in ENDPOINTS[self.KEY_SSO].items():
            endp = "{}/{}".format(endpoint_base_url, endpoint)
            expected_endpoints.append((endp, binding))

        idp_server = frontend._create_co_virtual_idp(context)
        sso_endpoints = idp_server.config._idp_endpoints[self.KEY_SSO]

        assert idp_server.config.entityid == expected_entityid
        assert all(sso in sso_endpoints for sso in expected_endpoints)

    def test_create_co_virtual_idp_with_entity_id_templates(self, frontend, context):
        frontend.idp_config['entityid'] = "{}/Saml2IDP/proxy.xml".format(BASE_URL)
        expected_entity_id = "{}/Saml2IDP/proxy.xml/{}".format(BASE_URL, self.CO)
        idp_server = frontend._create_co_virtual_idp(context)
        assert idp_server.config.entityid == expected_entity_id

        frontend.idp_config['entityid'] = "{}/<backend_name>/idp/<co_name>".format(BASE_URL)
        expected_entity_id = "{}/{}/idp/{}".format(BASE_URL, context.target_backend, self.CO)
        idp_server = frontend._create_co_virtual_idp(context)
        assert idp_server.config.entityid == expected_entity_id

    def test_register_endpoints(self, frontend, context):
        idp_server = frontend._create_co_virtual_idp(context)
        url_map = frontend.register_endpoints([self.BACKEND])
        all_idp_endpoints = [urlparse(endpoint[0]).path[1:] for
                             endpoint in
                             idp_server.config._idp_endpoints[self.KEY_SSO]]
        compiled_regex = [re.compile(regex) for regex, _ in url_map]

        for endpoint in all_idp_endpoints:
            assert any(pat.match(endpoint) for pat in compiled_regex)

    def test_register_endpoints_throws_error_in_case_duplicate_entity_ids(self, frontend):
        with pytest.raises(ValueError):
            frontend.register_endpoints([self.BACKEND, self.BACKEND_1])

    def test_register_endpoints_with_metadata_endpoints(self, frontend, context):
        frontend.idp_config['entityid'] = "{}/<backend_name>/idp/<co_name>".format(BASE_URL)
        frontend.config['entityid_endpoint'] = True
        idp_server_1 = frontend._create_co_virtual_idp(context)
        context_2 = self._make_context(context, self.BACKEND_1, self.CO)
        idp_server_2 = frontend._create_co_virtual_idp(context_2)

        url_map = frontend.register_endpoints([self.BACKEND, self.BACKEND_1])
        expected_idp_endpoints = [urlparse(endpoint[0]).path[1:] for server in [idp_server_1, idp_server_2]
                                  for endpoint in server.config._idp_endpoints[self.KEY_SSO]]
        for server in [idp_server_1, idp_server_2]:
            expected_idp_endpoints.append(urlparse(server.config.entityid).path[1:])

        compiled_regex = [re.compile(regex) for regex, _ in url_map]

        for endpoint in expected_idp_endpoints:
            assert any(pat.match(endpoint) for pat in compiled_regex)

    def test_co_static_attributes(self, frontend, context, internal_response,
                                  idp_conf, sp_conf):
        # Use the frontend and context fixtures to dynamically create the
        # proxy IdP server that would be created during a flow.
        idp_server = frontend._create_co_virtual_idp(context)

        # Use the context fixture to find the CO name and the backend name
        # and then use those to dynamically update the ipd_conf fixture.
        co_name = frontend._get_co_name(context)
        backend_name = context.target_backend
        idp_conf = frontend._add_endpoints_to_config(idp_conf, co_name, backend_name)
        idp_conf = frontend._add_entity_id(idp_conf, co_name, backend_name)

        # Use a utility function to serialize the idp_conf IdP configuration
        # fixture to a string and then dynamically update the sp_conf
        # SP configuration fixture with the metadata.
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        sp_config = SPConfig().load(sp_conf)

        # Use the updated sp_config fixture to generate a fake SP and then
        # use the fake SP to generate an authentication request aimed at the
        # proxy CO virtual IdP.
        fakesp = FakeSP(sp_config)
        destination, auth_req = fakesp.make_auth_req(
            idp_server.config.entityid,
            nameid_format=None,
            relay_state="relay_state",
            subject=None,
        )

        # Update the context with the authentication request.
        context.request = auth_req

        # Create the response arguments necessary for the IdP to respond to
        # the authentication request, update the request state and with it
        # the context, and then use the frontend fixture and the
        # internal_response fixture to handle the authentication response
        # and generate a response from the proxy IdP to the SP.
        resp_args = {
            "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT),
            "in_response_to": None,
            "destination": sp_config.endpoint(
                "assertion_consumer_service",
                binding=BINDING_HTTP_REDIRECT
            )[0],
            "sp_entity_id": sp_conf["entityid"],
            "binding": BINDING_HTTP_REDIRECT
        }
        request_state = frontend._create_state_data(context, resp_args, "")
        context.state[frontend.name] = request_state
        frontend.handle_authn_response(context, internal_response)

        # Verify that the frontend added the CO static SAML attributes to the
        # internal response.
        for attr, value in self.CO_STATIC_SAML_ATTRIBUTES.items():
            assert internal_response.attributes[attr] == value


class TestSubjectTypeToSamlNameIdFormat:
    def test_should_default_to_persistent(self):
        assert (
            subject_type_to_saml_nameid_format("unmatched")
            == NAMEID_FORMAT_PERSISTENT
        )

    def test_should_map_persistent(self):
        assert (
            subject_type_to_saml_nameid_format(NAMEID_FORMAT_PERSISTENT)
            == NAMEID_FORMAT_PERSISTENT
        )

    def test_should_map_transient(self):
        assert (
            subject_type_to_saml_nameid_format(NAMEID_FORMAT_TRANSIENT)
            == NAMEID_FORMAT_TRANSIENT
        )

    def test_should_map_emailaddress(self):
        assert (
            subject_type_to_saml_nameid_format(NAMEID_FORMAT_EMAILADDRESS)
            == NAMEID_FORMAT_EMAILADDRESS
        )

    def test_should_map_unspecified(self):
        assert (
            subject_type_to_saml_nameid_format(NAMEID_FORMAT_UNSPECIFIED)
            == NAMEID_FORMAT_UNSPECIFIED
        )

    def test_should_map_public(self):
        assert (
            subject_type_to_saml_nameid_format("public") == NAMEID_FORMAT_PERSISTENT
        )

    def test_should_map_pairwise(self):
        assert (
            subject_type_to_saml_nameid_format("pairwise") == NAMEID_FORMAT_TRANSIENT
        )
