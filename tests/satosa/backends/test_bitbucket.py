import json
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import pytest
import responses

from saml2.saml import NAMEID_FORMAT_TRANSIENT

from satosa.backends.bitbucket import BitBucketBackend
from satosa.internal import InternalData

BB_USER_RESPONSE = {
    "account_id": "bb_id",
    "is_staff": False,
    "username": "bb_username",
    "nickname": "bb_username",
    "display_name": "bb_first_name bb_last_name",
    "has_2fa_enabled": False,
    "created_on": "2019-10-12T09:14:00+0000"
}
BB_USER_EMAIL_RESPONSE = {
    "values": [
       {
            "email": "bb_username@example.com",
            "is_confirmed": True,
            "is_primary": True
        },
       {
            "email": "bb_username_1@example.com",
            "is_confirmed": True,
            "is_primary": False
        },
       {
            "email": "bb_username_2@example.com",
            "is_confirmed": False,
            "is_primary": False
        }
    ]
}
BASE_URL = "https://client.example.com"
AUTHZ_PAGE = 'bitbucket'
CLIENT_ID = "bitbucket_client_id"
BB_CONFIG = {
    'server_info': {
        'authorization_endpoint':
            'https://bitbucket.org/site/oauth2/authorize',
        'token_endpoint': 'https://bitbucket.org/site/oauth2/access_token',
        'user_endpoint': 'https://api.bitbucket.org/2.0/user'
    },
    'client_secret': 'bitbucket_secret',
    'base_url': BASE_URL,
    'state_encryption_  key': 'state_encryption_key',
    'encryption_key': 'encryption_key',
    'authz_page': AUTHZ_PAGE,
    'client_config': {'client_id': CLIENT_ID},
    'scope': ["account", "email"]

}
BB_RESPONSE_CODE = "the_bb_code"

INTERNAL_ATTRIBUTES = {
    'attributes': {
        'mail': {'bitbucket': ['email']},
        'subject-id': {'bitbucket': ['account_id']},
        'displayname': {'bitbucket': ['display_name']},
        'name': {'bitbucket': ['display_name']},
    }
}

mock_get_state = Mock(return_value="abcdef")


class TestBitBucketBackend(object):
    @pytest.fixture(autouse=True)
    def create_backend(self):
        self.bb_backend = BitBucketBackend(Mock(), INTERNAL_ATTRIBUTES,
                                           BB_CONFIG, "base_url", "bitbucket", None, None)

    @pytest.fixture
    def incoming_authn_response(self, context):
        context.path = 'bitbucket/sso/redirect'
        state_data = dict(state=mock_get_state.return_value)
        context.state[self.bb_backend.name] = state_data
        context.request = {
            "code": BB_RESPONSE_CODE,
            "state": mock_get_state.return_value
        }

        return context

    def setup_bitbucket_response(self):
        _user_endpoint = BB_CONFIG['server_info']['user_endpoint']
        responses.add(responses.GET,
                      _user_endpoint,
                      body=json.dumps(BB_USER_RESPONSE),
                      status=200,
                      content_type='application/json')

        responses.add(responses.GET,
                      '{}/emails'.format(_user_endpoint),
                      body=json.dumps(BB_USER_EMAIL_RESPONSE),
                      status=200,
                      content_type='application/json')

    def assert_expected_attributes(self):
        expected_attributes = {
            "subject-id": [BB_USER_RESPONSE["account_id"]],
            "name": [BB_USER_RESPONSE["display_name"]],
            "displayname": [BB_USER_RESPONSE["display_name"]],
            "mail": [BB_USER_EMAIL_RESPONSE["values"][0]["email"]],
        }

        context, internal_resp = self.bb_backend \
            .auth_callback_func \
            .call_args[0]
        assert internal_resp.attributes == expected_attributes

    def assert_token_request(self, request_args, state, **kwargs):
        assert request_args["code"] == BB_RESPONSE_CODE
        assert request_args["redirect_uri"] == "%s/%s" % (BASE_URL, AUTHZ_PAGE)
        assert request_args["state"] == mock_get_state.return_value
        assert state == mock_get_state.return_value

    def test_register_endpoints(self):
        url_map = self.bb_backend.register_endpoints()
        expected_url_map = [('^bitbucket$', self.bb_backend._authn_response)]
        assert url_map == expected_url_map

    def test_start_auth(self, context):
        context.path = 'bitbucket/sso/redirect'
        internal_request = InternalData(
            subject_type=NAMEID_FORMAT_TRANSIENT, requester='test_requester'
        )

        resp = self.bb_backend.start_auth(context,
                                          internal_request,
                                          mock_get_state)
        login_url = resp.message
        assert login_url.startswith(
                BB_CONFIG["server_info"]["authorization_endpoint"])
        expected_params = {
            "client_id": CLIENT_ID,
            "state": mock_get_state.return_value,
            "response_type": "code",
            "scope": " ".join(BB_CONFIG["scope"]),
            "redirect_uri": "%s/%s" % (BASE_URL, AUTHZ_PAGE)
        }
        actual_params = dict(parse_qsl(urlparse(login_url).query))
        assert actual_params == expected_params

    @responses.activate
    def test_authn_response(self, incoming_authn_response):
        self.setup_bitbucket_response()

        mock_do_access_token_request = Mock(
                return_value={"access_token": "bb access token"})
        self.bb_backend.consumer.do_access_token_request = \
            mock_do_access_token_request

        self.bb_backend._authn_response(incoming_authn_response)

        self.assert_expected_attributes()
        self.assert_token_request(**mock_do_access_token_request.call_args[1])

    @responses.activate
    def test_entire_flow(self, context):
        """
        Tests start of authentication (incoming auth req) and receiving auth
        response.
        """
        responses.add(responses.POST,
                      BB_CONFIG["server_info"]["token_endpoint"],
                      body=json.dumps({"access_token": "qwerty",
                                       "token_type": "bearer",
                                       "expires_in": 9999999999999}),
                      status=200,
                      content_type='application/json')
        self.setup_bitbucket_response()

        context.path = 'bitbucket/sso/redirect'
        internal_request = InternalData(
            subject_type=NAMEID_FORMAT_TRANSIENT, requester='test_requester'
        )

        self.bb_backend.start_auth(context, internal_request, mock_get_state)
        context.request = {
            "code": BB_RESPONSE_CODE,
            "state": mock_get_state.return_value
        }
        self.bb_backend._authn_response(context)
        self.assert_expected_attributes()
