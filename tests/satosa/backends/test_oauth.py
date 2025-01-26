import json
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import pytest
import responses

from saml2.saml import NAMEID_FORMAT_TRANSIENT

from satosa.backends.oauth import FacebookBackend
from satosa.internal import InternalData

FB_RESPONSE = {
    "id": "fb_id",
    "name": "fb_name",
    "first_name": "fb_first_name",
    "last_name": "fb_last_name",
    "picture": {
        "data": {
            "is_silhouette": False,
            "url": "fb_picture"
        }
    },
    "email": "fb_email",
    "verified": True,
    "gender": "fb_gender",
    "timezone": 2,
    "locale": "sv_SE",
    "updated_time": "2015-10-15T07:04:10+0000"
}
BASE_URL = "https://client.example.com"
AUTHZ_PAGE = 'facebook'
CLIENT_ID = "facebook_client_id"
FB_AUTH_ENDPOINT = "https://www.facebook.com/dialog/oauth"
FB_CONFIG = {
    'server_info': {
        'authorization_endpoint': FB_AUTH_ENDPOINT,
        'token_endpoint': 'https://graph.facebook.com/v2.5/oauth/access_token'
    },
    'client_secret': 'facebook_secret',
    'base_url': BASE_URL,
    'state_encryption_key': 'state_encryption_key',
    'encryption_key': 'encryption_key',
    'fields': ['id', 'name', 'first_name', 'last_name', 'middle_name', 'picture', 'email',
               'verified', 'gender', 'timezone', 'locale', 'updated_time'],
    'authz_page': AUTHZ_PAGE,
    'client_config': {'client_id': CLIENT_ID}
}
FB_RESPONSE_CODE = "the_fb_code"

INTERNAL_ATTRIBUTES = {
    'attributes': {
        'givenname': {'facebook': ['first_name']},
        'mail': {'facebook': ['email']},
        'edupersontargetedid': {'facebook': ['id']},
        'name': {'facebook': ['name']},
        'surname': {'facebook': ['last_name']},
        'gender': {'facebook': ['gender']}
    }
}

mock_get_state = Mock(return_value="abcdef")


class TestFacebookBackend(object):
    @pytest.fixture(autouse=True)
    def create_backend(self):
        self.fb_backend = FacebookBackend(Mock(), INTERNAL_ATTRIBUTES, FB_CONFIG, "base_url", "facebook", None, None)

    @pytest.fixture
    def incoming_authn_response(self, context):
        context.path = 'facebook/sso/redirect'
        state_data = dict(state=mock_get_state.return_value)
        context.state[self.fb_backend.name] = state_data
        context.request = {
            "code": FB_RESPONSE_CODE,
            "state": mock_get_state.return_value
        }

        return context

    def setup_facebook_response(self):
        responses.add(responses.GET,
                      "https://graph.facebook.com/v2.5/me",
                      body=json.dumps(FB_RESPONSE),
                      status=200,
                      content_type='application/json')

    def assert_expected_attributes(self):
        expected_attributes = {
            "edupersontargetedid": [FB_RESPONSE["id"]],
            "surname": [FB_RESPONSE["last_name"]],
            "name": [FB_RESPONSE["name"]],
            "mail": [FB_RESPONSE["email"]],
            "givenname": [FB_RESPONSE["first_name"]],
            "gender": [FB_RESPONSE["gender"]],
        }

        context, internal_resp = self.fb_backend.auth_callback_func.call_args[0]
        assert internal_resp.attributes == expected_attributes

    def assert_token_request(self, request_args, state, **kwargs):
        assert request_args["code"] == FB_RESPONSE_CODE
        assert request_args["redirect_uri"] == "%s/%s" % (BASE_URL, AUTHZ_PAGE)
        assert request_args["state"] == mock_get_state.return_value
        assert state == mock_get_state.return_value

    def test_register_endpoints(self):
        url_map = self.fb_backend.register_endpoints()
        expected_url_map = [('^facebook$', self.fb_backend._authn_response)]
        assert url_map == expected_url_map

    def test_start_auth(self, context):
        context.path = 'facebook/sso/redirect'
        internal_request = InternalData(
            subject_type=NAMEID_FORMAT_TRANSIENT, requester='test_requester'
        )

        resp = self.fb_backend.start_auth(context, internal_request, mock_get_state)
        login_url = resp.message
        assert login_url.startswith(FB_AUTH_ENDPOINT)
        expected_params = {
            "client_id": CLIENT_ID,
            "state": mock_get_state.return_value,
            "response_type": "code",
            "redirect_uri": "%s/%s" % (BASE_URL, AUTHZ_PAGE)
        }
        actual_params = dict(parse_qsl(urlparse(login_url).query))
        assert actual_params == expected_params

    @responses.activate
    def test_authn_response(self, incoming_authn_response):
        self.setup_facebook_response()

        mock_do_access_token_request = Mock(return_value={"access_token": "fb access token"})
        self.fb_backend.consumer.do_access_token_request = mock_do_access_token_request

        self.fb_backend._authn_response(incoming_authn_response)

        self.assert_expected_attributes()
        self.assert_token_request(**mock_do_access_token_request.call_args[1])

    @responses.activate
    def test_entire_flow(self, context):
        """Tests start of authentication (incoming auth req) and receiving auth response."""
        responses.add(responses.POST,
                      "https://graph.facebook.com/v2.5/oauth/access_token",
                      body=json.dumps({"access_token": "qwerty",
                                       "token_type": "bearer",
                                       "expires_in": 9999999999999}),
                      status=200,
                      content_type='application/json')
        self.setup_facebook_response()

        context.path = 'facebook/sso/redirect'
        internal_request = InternalData(
            subject_type=NAMEID_FORMAT_TRANSIENT, requester='test_requester'
        )

        self.fb_backend.start_auth(context, internal_request, mock_get_state)
        context.request = {
            "code": FB_RESPONSE_CODE,
            "state": mock_get_state.return_value
        }
        self.fb_backend._authn_response(context)
        self.assert_expected_attributes()
