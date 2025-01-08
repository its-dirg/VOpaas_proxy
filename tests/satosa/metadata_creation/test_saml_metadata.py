import copy
from base64 import urlsafe_b64encode

import pytest
from saml2.config import SPConfig, Config
from saml2.mdstore import InMemoryMetaData
from saml2.metadata import entity_descriptor
from saml2.sigver import security_context
from saml2.time_util import in_a_while

from satosa.metadata_creation.saml_metadata import create_entity_descriptors, create_signed_entities_descriptor, \
    create_signed_entity_descriptor
from satosa.satosa_config import SATOSAConfig
from tests.conftest import BASE_URL
from tests.util import create_metadata_from_config_dict


class TestCreateEntityDescriptors:
    def assert_single_sign_on_endpoints_for_saml_frontend(self, entity_descriptor, saml_frontend_config, backend_names):
        metadata = InMemoryMetaData(None, str(entity_descriptor))
        metadata.load()
        sso = metadata.service(saml_frontend_config["config"]["idp_config"]["entityid"], "idpsso_descriptor",
                               "single_sign_on_service")

        for backend_name in backend_names:
            for binding, path in saml_frontend_config["config"]["endpoints"]["single_sign_on_service"].items():
                sso_urls_for_binding = [endpoint["location"] for endpoint in sso[binding]]
                expected_url = "{}/{}/{}".format(BASE_URL, backend_name, path)
                assert expected_url in sso_urls_for_binding

    def assert_single_sign_on_endpoints_for_saml_mirror_frontend(self, entity_descriptors, encoded_target_entity_id,
                                                                 saml_mirror_frontend_config, backend_names):
        expected_entity_id = saml_mirror_frontend_config["config"]["idp_config"][
                                 "entityid"] + "/" + encoded_target_entity_id
        metadata = InMemoryMetaData(None, None)
        for ed in entity_descriptors:
            metadata.parse(str(ed))
        sso = metadata.service(expected_entity_id, "idpsso_descriptor", "single_sign_on_service")

        for backend_name in backend_names:
            for binding, path in saml_mirror_frontend_config["config"]["endpoints"]["single_sign_on_service"].items():
                sso_urls_for_binding = [endpoint["location"] for endpoint in sso[binding]]
                expected_url = "{}/{}/{}/{}".format(BASE_URL, backend_name, encoded_target_entity_id, path)
                assert expected_url in sso_urls_for_binding

    def assert_single_logout_endpoints_for_saml_frontend(self, entity_descriptor, saml_frontend_config, backend_names):
        metadata = InMemoryMetaData(None, str(entity_descriptor))
        metadata.load()
        slo = metadata.service(saml_frontend_config["config"]["idp_config"]["entityid"], "idpsso_descriptor",
                               "single_logout_service")

        for backend_name in backend_names:
            for binding, path in saml_frontend_config["config"]["endpoints"]["single_logout_service"].items():
                slo_urls_for_binding = [endpoint["location"] for endpoint in slo[binding]]
                expected_url = "{}/{}/{}".format(BASE_URL, backend_name, path)
                assert expected_url in slo_urls_for_binding

    def assert_assertion_consumer_service_endpoints_for_saml_backend(self, entity_descriptor, saml_backend_config):
        metadata = InMemoryMetaData(None, str(entity_descriptor))
        metadata.load()
        acs = metadata.service(saml_backend_config["config"]["sp_config"]["entityid"], "spsso_descriptor",
                               "assertion_consumer_service")
        for url, binding in saml_backend_config["config"]["sp_config"]["service"]["sp"]["endpoints"][
            "assertion_consumer_service"]:
            assert acs[binding][0]["location"] == url

    def assert_single_logout_endpoints_for_saml_backend(self, entity_descriptor, saml_backend_config):
        metadata = InMemoryMetaData(None, str(entity_descriptor))
        metadata.load()
        slo = metadata.service(saml_backend_config["config"]["sp_config"]["entityid"], "spsso_descriptor",
                               "single_logout_service")
        for url, binding in saml_backend_config["config"]["sp_config"]["service"]["sp"]["endpoints"][
            "single_logout_service"]:
            assert slo[binding][0]["location"] == url

    def test_saml_frontend_with_saml_backend(self, satosa_config_dict, saml_frontend_config, saml_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_frontend_config["name"]]) == 1
        entity_descriptor = frontend_metadata[saml_frontend_config["name"]][0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [saml_backend_config["name"]])
        self.assert_single_logout_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                              [saml_backend_config["name"]])
        assert len(backend_metadata) == 1
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)
        self.assert_single_logout_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)

    def test_saml_frontend_with_oidc_backend(self, satosa_config_dict, saml_frontend_config, oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_frontend_config["name"]]) == 1
        entity_descriptor = frontend_metadata[saml_frontend_config["name"]][0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [oidc_backend_config["name"]])
        self.assert_single_logout_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                              [oidc_backend_config["name"]])
        # OIDC backend does not produce any SAML metadata
        assert not backend_metadata

    def test_saml_frontend_with_multiple_backends(self, satosa_config_dict, saml_frontend_config, saml_backend_config,
                                                  oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config, oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_frontend_config["name"]]) == 1
        entity_descriptor = frontend_metadata[saml_frontend_config["name"]][0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [saml_backend_config["name"],
                                                                oidc_backend_config["name"]])
        self.assert_single_logout_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                              [oidc_backend_config["name"]])
        # only the SAML backend produces SAML metadata
        assert len(backend_metadata) == 1
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)
        self.assert_single_logout_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)

    def test_saml_mirror_frontend_with_saml_backend_with_multiple_target_providers(self, satosa_config_dict, idp_conf,
                                                                                   saml_mirror_frontend_config,
                                                                                   saml_backend_config):
        idp_conf2 = copy.deepcopy(idp_conf)
        idp_conf2["entityid"] = "https://idp2.example.com"
        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        saml_backend_config["config"]["sp_config"]["metadata"] = {"inline": [create_metadata_from_config_dict(idp_conf),
                                                                             create_metadata_from_config_dict(
                                                                                 idp_conf2)]}
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_mirror_frontend_config["name"]]) == 2

        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        for target_entity_id in [idp_conf["entityid"], idp_conf2["entityid"]]:
            encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
            self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(entity_descriptors, encoded_target_entity_id,
                                                                          saml_mirror_frontend_config,
                                                                          [saml_backend_config["name"]])
        assert len(backend_metadata) == 1
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)
        self.assert_single_logout_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)

    def test_saml_mirror_frontend_with_oidc_backend(self, satosa_config_dict, saml_mirror_frontend_config,
                                                    oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_mirror_frontend_config["name"]]) == 1
        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        target_entity_id = oidc_backend_config["config"]["provider_metadata"]["issuer"]
        encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
        self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(entity_descriptors, encoded_target_entity_id,
                                                                      saml_mirror_frontend_config,
                                                                      [oidc_backend_config["name"]])

        # OIDC backend does not produce any SAML metadata
        assert not backend_metadata

    def test_saml_mirror_frontend_with_multiple_backends(self, satosa_config_dict, idp_conf,
                                                         saml_mirror_frontend_config,
                                                         saml_backend_config, oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        saml_backend_config["config"]["sp_config"]["metadata"] = {
            "inline": [create_metadata_from_config_dict(idp_conf)]}
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config, oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_mirror_frontend_config["name"]]) == 2
        params = zip([idp_conf["entityid"], oidc_backend_config["config"]["provider_metadata"]["issuer"]],
                     [saml_backend_config["name"], oidc_backend_config["name"]])
        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        for target_entity_id, backend_name in params:
            encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
            self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(entity_descriptors, encoded_target_entity_id,
                                                                          saml_mirror_frontend_config,
                                                                          [backend_name])

        # only the SAML backend produces SAML metadata
        assert len(backend_metadata)
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)
        self.assert_single_logout_endpoints_for_saml_backend(
            backend_metadata[saml_backend_config["name"]][0],
            saml_backend_config)

    def test_two_saml_frontends(self, satosa_config_dict, saml_frontend_config, saml_mirror_frontend_config,
                                oidc_backend_config):

        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config, saml_mirror_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 2

        saml_entities = frontend_metadata[saml_frontend_config["name"]]
        assert len(saml_entities) == 1
        entity_descriptor = saml_entities[0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [oidc_backend_config["name"]])
        self.assert_single_logout_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                              [oidc_backend_config["name"]])

        mirrored_saml_entities = frontend_metadata[saml_mirror_frontend_config["name"]]
        assert len(mirrored_saml_entities) == 1
        target_entity_id = oidc_backend_config["config"]["provider_metadata"]["issuer"]
        encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
        self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(mirrored_saml_entities, encoded_target_entity_id,
                                                                      saml_mirror_frontend_config,
                                                                      [oidc_backend_config["name"]])

        # OIDC backend does not produce any SAML metadata
        assert not backend_metadata

    def test_create_mirrored_metadata_does_not_contain_target_contact_info(self, satosa_config_dict, idp_conf,
                                                                           saml_mirror_frontend_config,
                                                                           saml_backend_config):

        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        saml_backend_config["config"]["sp_config"]["metadata"] = {
            "inline": [create_metadata_from_config_dict(idp_conf)]}
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_entity_descriptors(satosa_config)

        assert len(frontend_metadata) == 1
        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        metadata = InMemoryMetaData(None, str(entity_descriptors[0]))
        metadata.load()

        entity_info = list(metadata.values())[0]
        expected_entity_info = saml_mirror_frontend_config["config"]["idp_config"]
        assert len(entity_info["contact_person"]) == len(expected_entity_info["contact_person"])
        for i, contact in enumerate(expected_entity_info["contact_person"]):
            assert entity_info["contact_person"][i]["contact_type"] == contact["contact_type"]
            assert entity_info["contact_person"][i]["email_address"][0]["text"] == contact["email_address"][0]
            assert entity_info["contact_person"][i]["given_name"]["text"] == contact["given_name"]
            assert entity_info["contact_person"][i]["sur_name"]["text"] == contact["sur_name"]

        expected_org_info = expected_entity_info["organization"]
        assert entity_info["organization"]["organization_display_name"][0]["text"] == \
               expected_org_info["display_name"][0][0]
        assert entity_info["organization"]["organization_name"][0]["text"] == expected_org_info["name"][0][0]
        assert entity_info["organization"]["organization_url"][0]["text"] == expected_org_info["url"][0][0]


class TestCreateSignedEntitiesDescriptor:
    @pytest.fixture
    def entity_desc(self, sp_conf):
        return entity_descriptor(SPConfig().load(sp_conf))

    @pytest.fixture
    def verification_security_context(self, cert_and_key):
        conf = Config()
        conf.cert_file = cert_and_key[0]
        return security_context(conf)

    @pytest.fixture
    def signature_security_context(self, cert_and_key):
        conf = Config()
        conf.cert_file = cert_and_key[0]
        conf.key_file = cert_and_key[1]
        return security_context(conf)

    def test_signed_metadata(self, entity_desc, signature_security_context, verification_security_context):
        signed_metadata = create_signed_entities_descriptor([entity_desc, entity_desc], signature_security_context)

        md = InMemoryMetaData(None, security=verification_security_context)
        md.parse(signed_metadata)
        assert md.signed() is True
        assert md.parse_and_check_signature(signed_metadata) is True
        assert not md.entities_descr.valid_until

    def test_valid_for(self, entity_desc, signature_security_context):
        valid_for = 4  # metadata valid for 4 hours
        expected_validity = in_a_while(hours=valid_for)
        signed_metadata = create_signed_entities_descriptor([entity_desc], signature_security_context,
                                                            valid_for=valid_for)

        md = InMemoryMetaData(None)
        md.parse(signed_metadata)
        assert md.entities_descr.valid_until == expected_validity


class TestCreateSignedEntityDescriptor:
    @pytest.fixture
    def entity_desc(self, sp_conf):
        return entity_descriptor(SPConfig().load(sp_conf))

    @pytest.fixture
    def verification_security_context(self, cert_and_key):
        conf = Config()
        conf.cert_file = cert_and_key[0]
        return security_context(conf)

    @pytest.fixture
    def signature_security_context(self, cert_and_key):
        conf = Config()
        conf.cert_file = cert_and_key[0]
        conf.key_file = cert_and_key[1]
        return security_context(conf)

    def test_signed_metadata(self, entity_desc, signature_security_context, verification_security_context):
        signed_metadata = create_signed_entity_descriptor(entity_desc, signature_security_context)

        md = InMemoryMetaData(None, security=verification_security_context)
        md.parse(signed_metadata)
        assert md.signed() is True
        assert md.parse_and_check_signature(signed_metadata) is True
        assert not md.entity_descr.valid_until

    def test_valid_for(self, entity_desc, signature_security_context):
        valid_for = 4  # metadata valid for 4 hours
        expected_validity = in_a_while(hours=valid_for)
        signed_metadata = create_signed_entity_descriptor(entity_desc, signature_security_context,
                                                          valid_for=valid_for)

        md = InMemoryMetaData(None)
        md.parse(signed_metadata)
        assert md.entity_descr.valid_until == expected_validity
