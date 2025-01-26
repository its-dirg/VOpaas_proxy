"""
OAuth backend for Orcid
"""
import json
import requests
import logging
from urllib.parse import urljoin

from oic.utils.authn.authn_context import UNSPECIFIED
from oic.oauth2.consumer import stateID
from oic.oauth2.message import AuthorizationResponse

from satosa.backends.oauth import _OAuthBackend
from satosa.internal import InternalData
from satosa.internal import AuthenticationInformation
from satosa.util import rndstr

logger = logging.getLogger(__name__)


class OrcidBackend(_OAuthBackend):
    """Orcid OAuth 2.0 backend"""

    def __init__(self, outgoing, internal_attributes, config, base_url, name, storage, logout_callback_func):
        """Orcid backend constructor
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
        super().__init__(outgoing, internal_attributes, config, base_url, name, 'orcid', 'orcid',
                         storage, logout_callback_func)

    def get_request_args(self, get_state=stateID):
        oauth_state = get_state(self.config["base_url"], rndstr().encode())
        request_args = {
            "client_id": self.config['client_config']['client_id'],
            "redirect_uri": self.redirect_url,
            "scope": ' '.join(self.config['scope']),
            "state": oauth_state,
        }
        return request_args

    def auth_info(self, requrest):
        return AuthenticationInformation(
            UNSPECIFIED, None,
            self.config['server_info']['authorization_endpoint'])

    def _authn_response(self, context):
        state_data = context.state[self.name]
        aresp = self.consumer.parse_response(
            AuthorizationResponse, info=json.dumps(context.request))
        self._verify_state(aresp, state_data, context.state)

        rargs = {"code": aresp["code"], "redirect_uri": self.redirect_url,
                 "state": state_data["state"]}

        atresp = self.consumer.do_access_token_request(
            request_args=rargs, state=aresp['state'])

        user_info = self.user_information(
            atresp['access_token'], atresp['orcid'], atresp.get('name'))
        internal_response = InternalData(
            auth_info=self.auth_info(context.request))
        internal_response.attributes = self.converter.to_internal(
            self.external_type, user_info)
        internal_response.subject_id = user_info[self.user_id_attr]
        return self.auth_callback_func(context, internal_response)

    def user_information(self, access_token, orcid, name=None):
        base_url = self.config['server_info']['user_info']
        url = urljoin(base_url, '{}/person'.format(orcid))
        headers = {
            'Accept': 'application/orcid+json',
            'Authorization': "Bearer {}".format(access_token)
        }
        r = requests.get(url, headers=headers)
        r = r.json()
        emails, addresses = r['emails']['email'], r['addresses']['address']
        rname = r.get('name') or {}
        ret = dict(
            address=', '.join([e['country']['value'] for e in addresses]),
            displayname=name,
            edupersontargetedid=orcid, orcid=orcid,
            mail=' '.join([e['email'] for e in emails]),
            name=name,
            givenname=(rname.get('given-names') or {}).get('value'),
            surname=(rname.get('family-name') or {}).get('value'),
        )

        return ret
