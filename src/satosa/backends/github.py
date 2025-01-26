"""
OAuth backend for LinkedIn
"""
import json
import logging
import requests

from oic.utils.authn.authn_context import UNSPECIFIED
from oic.oauth2.consumer import stateID
from oic.oauth2.message import AuthorizationResponse

from satosa.backends.oauth import _OAuthBackend
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.util import rndstr

logger = logging.getLogger(__name__)


class GitHubBackend(_OAuthBackend):
    """GitHub OAuth 2.0 backend"""

    def __init__(self, outgoing, internal_attributes, config, base_url, name, storage,
                 logout_callback_func):
        """GitHub backend constructor
        :param outgoing: Callback should be called by the module after the
            authorization in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal
            attribute names and the names returned by underlying IdP's/OP's as
            well as what attributes the calling SP's and RP's expects namevice.
        :param config: configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin
        :param storage: storage to hold the backend session information
        :param logout_callback_func: Callback should be called by the module after the logout
        in the backend is done. This may trigger log out flow for all the frontends associated
        with the backend session

        :type outgoing:
            (satosa.context.Context, satosa.internal.InternalData) ->
            satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str] | str]
        :type base_url: str
        :type name: str
        :type storage: satosa.storage.Storage
        :type logout_callback_func: str
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        """
        config.setdefault('response_type', 'code')
        config['verify_accesstoken_state'] = False
        super().__init__(outgoing, internal_attributes, config, base_url, name, 'github', 'id',
                         storage, logout_callback_func)

    def start_auth(self, context, internal_request, get_state=stateID):
        """
        :param get_state: Generates a state to be used in authentication call

        :type get_state: Callable[[str, bytes], str]
        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Redirect
        """
        oauth_state = get_state(self.config["base_url"], rndstr().encode())
        context.state[self.name] = dict(state=oauth_state)

        request_args = dict(
            client_id=self.config['client_config']['client_id'],
            redirect_uri=self.redirect_url,
            state=oauth_state,
            allow_signup=self.config.get('allow_signup', False))
        scope = ' '.join(self.config['scope'])
        if scope:
            request_args['scope'] = scope

        cis = self.consumer.construct_AuthorizationRequest(
            request_args=request_args)
        return Redirect(cis.request(self.consumer.authorization_endpoint))

    def auth_info(self, requrest):
        return AuthenticationInformation(
            UNSPECIFIED, None,
            self.config['server_info']['authorization_endpoint'])

    def _authn_response(self, context):
        state_data = context.state[self.name]
        aresp = self.consumer.parse_response(
            AuthorizationResponse, info=json.dumps(context.request))
        self._verify_state(aresp, state_data, context.state)
        url = self.config['server_info']['token_endpoint']
        data = dict(
            code=aresp['code'],
            redirect_uri=self.redirect_url,
            client_id=self.config['client_config']['client_id'],
            client_secret=self.config['client_secret'], )
        headers = {'Accept': 'application/json'}

        r = requests.post(url, data=data, headers=headers)
        response = r.json()
        if self.config.get('verify_accesstoken_state', True):
            self._verify_state(response, state_data, context.state)

        user_info = self.user_information(response["access_token"])
        auth_info = self.auth_info(context.request)
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = self.converter.to_internal(
            self.external_type, user_info)
        internal_response.subject_id = str(user_info[self.user_id_attr])
        return self.auth_callback_func(context, internal_response)

    def user_information(self, access_token):
        url = self.config['server_info']['user_info']
        headers = {'Authorization': 'token {}'.format(access_token)}
        r = requests.get(url, headers=headers)
        ret = r.json()
        ret['id'] = str(ret['id'])
        return ret
