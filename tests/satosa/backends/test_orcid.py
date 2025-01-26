import json
import pytest
import responses

from satosa.backends.orcid import OrcidBackend
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from unittest.mock import Mock
from urllib.parse import urljoin, urlparse, parse_qsl

ORCID_PERSON_ID = "0000-0000-0000-0000"
ORCID_PERSON_GIVEN_NAME = "orcid_given_name"
ORCID_PERSON_FAMILY_NAME = "orcid_family_name"
ORCID_PERSON_NAME = "{} {}".format(
    ORCID_PERSON_GIVEN_NAME, ORCID_PERSON_FAMILY_NAME)
ORCID_PERSON_EMAIL = "orcid_email"
ORCID_PERSON_COUNTRY = "XX"

mock_get_state = Mock(return_value="abcdef")


class TestOrcidBackend(object):
    @pytest.fixture(autouse=True)
    def create_backend(self, internal_attributes, backend_config):
        self.orcid_backend = OrcidBackend(
            Mock(),
            internal_attributes,
            backend_config,
            backend_config["base_url"],
            "orcid",
            None,
            None
        )

    @pytest.fixture
    def backend_config(self):
        return {
            "authz_page": 'orcid/auth/callback',
            "base_url": "https://client.example.com",
            "client_config": {"client_id": "orcid_client_id"},
            "client_secret": "orcid_secret",
            "scope": ["/authenticate"],
            "response_type": "code",
            "server_info": {
                "authorization_endpoint": "https://orcid.org/oauth/authorize",
                "token_endpoint": "https://pub.orcid.org/oauth/token",
                "user_info": "https://pub.orcid.org/v2.0/"
            }
        }

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "address": {"orcid": ["address"]},
                "displayname": {"orcid": ["name"]},
                "edupersontargetedid": {"orcid": ["orcid"]},
                "givenname": {"orcid": ["givenname"]},
                "mail": {"orcid": ["mail"]},
                "name": {"orcid": ["name"]},
                "surname": {"orcid": ["surname"]},
            }
        }

    @pytest.fixture
    def userinfo(self):
        return {
            "name": {
                "given-names": {"value": ORCID_PERSON_GIVEN_NAME},
                "family-name": {"value": ORCID_PERSON_FAMILY_NAME},
            },
            "emails": {
                "email": [
                    {
                        "email": ORCID_PERSON_EMAIL,
                        "verified": True,
                        "primary": True
                    }
                ]
            },
            "addresses": {
                "address": [
                    {"country": {"value": ORCID_PERSON_COUNTRY}}
                ]
            }
        }

    @pytest.fixture
    def userinfo_private(self):
        return {
            "name": {
                "given-names": {"value": ORCID_PERSON_GIVEN_NAME},
                "family-name": {"value": ORCID_PERSON_FAMILY_NAME},
            },
            "emails": {
                "email": [
                ]
            },
            "addresses": {
                "address": [
                ]
            }
        }

    def assert_expected_attributes(self, user_claims, actual_attributes):
        print(user_claims)
        print(actual_attributes)

        expected_attributes = {
            "address": [ORCID_PERSON_COUNTRY],
            "displayname": [ORCID_PERSON_NAME],
            "edupersontargetedid": [ORCID_PERSON_ID],
            "givenname": [ORCID_PERSON_GIVEN_NAME],
            "mail": [ORCID_PERSON_EMAIL],
            "name": [ORCID_PERSON_NAME],
            "surname": [ORCID_PERSON_FAMILY_NAME],
        }

        assert actual_attributes == expected_attributes

    def setup_token_endpoint(self, token_endpoint_url):
        token_response = {
            "access_token": "orcid_access_token",
            "token_type": "bearer",
            "expires_in": 9999999999999,
            "name": ORCID_PERSON_NAME,
            "orcid": ORCID_PERSON_ID
        }

        responses.add(
            responses.POST,
            token_endpoint_url,
            body=json.dumps(token_response),
            status=200,
            content_type="application/json"
        )

    def setup_userinfo_endpoint(self, userinfo_endpoint_url, userinfo):
        responses.add(
            responses.GET,
            urljoin(userinfo_endpoint_url,
                    '{}/person'.format(ORCID_PERSON_ID)),
            body=json.dumps(userinfo),
            status=200,
            content_type="application/json"
        )

    @pytest.fixture
    def incoming_authn_response(self, context, backend_config):
        context.path = backend_config["authz_page"]
        state_data = dict(state=mock_get_state.return_value)
        context.state[self.orcid_backend.name] = state_data
        context.request = {
            "code": "the_orcid_code",
            "state": mock_get_state.return_value
        }

        return context

    def test_start_auth(self, context, backend_config):
        auth_response = self.orcid_backend.start_auth(
            context, None, mock_get_state)
        assert isinstance(auth_response, Response)

        login_url = auth_response.message
        parsed = urlparse(login_url)
        assert login_url.startswith(
            backend_config["server_info"]["authorization_endpoint"])
        auth_params = dict(parse_qsl(parsed.query))
        assert auth_params["scope"] == " ".join(backend_config["scope"])
        assert auth_params["response_type"] == backend_config["response_type"]
        assert auth_params["client_id"] == backend_config["client_config"]["client_id"]
        assert auth_params["redirect_uri"] == "{}/{}".format(
            backend_config["base_url"],
            backend_config["authz_page"]
        )
        assert auth_params["state"] == mock_get_state.return_value

    @responses.activate
    def test_authn_response(self, backend_config, userinfo, incoming_authn_response):
        self.setup_token_endpoint(
            backend_config["server_info"]["token_endpoint"])
        self.setup_userinfo_endpoint(
            backend_config["server_info"]["user_info"], userinfo)

        self.orcid_backend._authn_response(incoming_authn_response)

        args = self.orcid_backend.auth_callback_func.call_args[0]
        assert isinstance(args[0], Context)
        assert isinstance(args[1], InternalData)

        self.assert_expected_attributes(userinfo, args[1].attributes)

    @responses.activate
    def test_user_information(self, context, backend_config, userinfo):
        self.setup_userinfo_endpoint(
            backend_config["server_info"]["user_info"],
            userinfo
        )

        user_attributes = self.orcid_backend.user_information(
            "orcid_access_token",
            ORCID_PERSON_ID,
            ORCID_PERSON_NAME
        )

        assert user_attributes["address"] == ORCID_PERSON_COUNTRY
        assert user_attributes["displayname"] == ORCID_PERSON_NAME
        assert user_attributes["edupersontargetedid"] == ORCID_PERSON_ID
        assert user_attributes["orcid"] == ORCID_PERSON_ID
        assert user_attributes["mail"] == ORCID_PERSON_EMAIL
        assert user_attributes["givenname"] == ORCID_PERSON_GIVEN_NAME
        assert user_attributes["surname"] == ORCID_PERSON_FAMILY_NAME

    @responses.activate
    def test_user_information_private(self, context, backend_config, userinfo_private):
        self.setup_userinfo_endpoint(
            backend_config["server_info"]["user_info"],
            userinfo_private
        )

        user_attributes = self.orcid_backend.user_information(
            "orcid_access_token",
            ORCID_PERSON_ID,
            ORCID_PERSON_NAME
        )

        assert user_attributes["address"] == ""
        assert user_attributes["mail"] == ""
