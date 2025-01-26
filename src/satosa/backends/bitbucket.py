"""
OAuth backend for BitBucket
"""
import json
import logging
import requests

from oic.utils.authn.authn_context import UNSPECIFIED
from oic.oauth2.consumer import stateID

from satosa.backends.oauth import _OAuthBackend
from satosa.internal import AuthenticationInformation

logger = logging.getLogger(__name__)


class BitBucketBackend(_OAuthBackend):
    """BitBucket OAuth 2.0 backend"""

    logprefix = "BitBucket Backend:"

    def __init__(self, outgoing, internal_attributes, config, base_url, name, storage, logout_callback_func):
        """BitBucket backend constructor
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
        super().__init__(outgoing, internal_attributes, config, base_url, name, 'bitbucket', 'account_id',
                         storage, logout_callback_func)

    def get_request_args(self, get_state=stateID):
        request_args = super().get_request_args(get_state=get_state)

        client_id = self.config["client_config"]["client_id"]
        extra_args = {
            arg_name: arg_val
            for arg_name in ["auth_type", "scope"]
            for arg_val in [self.config.get(arg_name, [])]
            if arg_val
        }
        extra_args.update({"client_id": client_id})
        request_args.update(extra_args)
        return request_args

    def auth_info(self, request):
        return AuthenticationInformation(
            UNSPECIFIED, None,
            self.config['server_info']['authorization_endpoint'])

    def user_information(self, access_token):
        url = self.config['server_info']['user_endpoint']
        email_url = "{}/emails".format(url)
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
        resp = requests.get(url, headers=headers)
        data = json.loads(resp.text)
        if 'email' in self.config['scope']:
            resp = requests.get(email_url, headers=headers)
            emails = json.loads(resp.text)
            data.update({
                'email': [e for e in [d.get('email')
                                      for d in emails.get('values')
                                      if d.get('is_primary')
                                      ]
                          ],
                'email_confirmed': [e for e in [d.get('email')
                                                for d in emails.get('values')
                                                if d.get('is_confirmed')
                                                ]
                                    ]
                })
        return data
