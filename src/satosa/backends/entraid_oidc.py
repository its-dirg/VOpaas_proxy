"""
Microsoft backend module for Entra ID OIDC.
"""

import logging
from datetime import datetime
from urllib.parse import urlparse

import satosa.logging_util as lu
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.backends.base import BackendModule
from satosa.backends.oauth import get_metadata_desc_for_oauth_backend
from satosa.exception import SATOSAAuthenticationError, SATOSAError
from satosa.response import Redirect

from oic.utils.authn.authn_context import UNSPECIFIED
from secrets import token_urlsafe

import msal

logger = logging.getLogger(__name__)

AUTH_CODE_FLOW_STATE_KEY = "auth_code_flow"


class EntraIDOIDCBackend(BackendModule):
    """
    Microsoft module for Entra ID OIDC
    """

    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name):
        """
        EntraID OIDC backend module.
        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param config: Configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin

        :type auth_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str]]
        :type base_url: str
        :type name: str
        """
        super().__init__(auth_callback_func, internal_attributes, base_url, name)
        self.auth_callback_func = auth_callback_func
        self.config = config
        self.client = _create_client(config)
        try:
            self.redirect_uri = self.config["redirect_uri"]
        except KeyError:
            raise SATOSAError("Missing redirect_uri")

    def start_auth(self, context, *args, **kwargs):
        """
        See super class method satosa.backends.base#start_auth
        :type context: satosa.context.Context
        :type request_info: satosa.internal.InternalData
        """                
        scopes = self.config.get("scopes", ["User.Read"])

        csrf_protection = token_urlsafe(32)

        auth_code_flow = _initiate_auth_code_flow(
            self.client,
            scopes=scopes,
            redirect_uri=self.redirect_uri,
            state=csrf_protection,
            **self.config["client"].get("initiate_auth_code_flow_args", {}),
        )

        context.state[self.name] = {AUTH_CODE_FLOW_STATE_KEY: auth_code_flow}

        return Redirect(auth_code_flow.get("auth_uri"))

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        url_map = []

        redirect_path = urlparse(self.redirect_uri).path
        if not redirect_path:
            raise SATOSAError("Missing path in redirect uri")

        url_map.append(("^%s$" % redirect_path.lstrip("/"), self.response_endpoint))
        return url_map

    def _check_error_response(self, response, context):
        """
        Check if the response is an OAuth error response.
        :param response: the OIDC response
        :type response: oic.oic.message
        :raise SATOSAAuthenticationError: if the response is an OAuth error response
        """
        if "error" in response:
            msg = "{name} error: {error} {description}".format(
                name=type(response).__name__,
                error=response["error"],
                description=response.get("error_description", ""),
            )
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(context.state, "Access denied")

    def response_endpoint(self, context, *args):
        """
        Handles the authentication response from the OP.
        :type context: satosa.context.Context
        :type args: Any
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :param args: None
        :return:
        """
        backend_state = context.state[self.name]
        auth_code_flow = backend_state.get(AUTH_CODE_FLOW_STATE_KEY, {})

        if not auth_code_flow:
            raise SATOSAAuthenticationError(context.state, "No auth_code_flow found.")

        token = self.client.acquire_token_by_auth_code_flow(
            auth_code_flow, context.request
        )

        self._check_error_response(token, context)
        id_token_claims = token.get("id_token_claims")

        if not id_token_claims:
            raise SATOSAAuthenticationError(context.state, "No user info available.")

        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(context.state),
            message=f"Claims returned: {id_token_claims}",
        )
        logger.debug(logline)

        internal_resp = self._translate_response(
            id_token_claims, id_token_claims["iss"]
        )

        del context.state[self.name]
        return self.auth_callback_func(context, internal_resp)

    def _translate_response(self, response, issuer):
        """
        Translates oidc response to SATOSA internal response.
        :type response: dict[str, str]
        :type issuer: str
        :type subject_type: str
        :rtype: InternalData

        :param response: Dictioary with attribute name as key.
        :param issuer: The oidc op that gave the repsonse.
        :param subject_type: public or pairwise according to oidc standard.
        :return: A SATOSA internal response.
        """
        auth_info = AuthenticationInformation(UNSPECIFIED, str(datetime.now()), issuer)
        internal_resp = InternalData(auth_info=auth_info)
        internal_resp.attributes = self.converter.to_internal("openid", response)
        internal_resp.subject_id = response["sub"]
        return internal_resp

    def get_metadata_desc(self):
        """
        See satosa.backends.oauth.get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        return get_metadata_desc_for_oauth_backend(self.config["issuer"], self.config)


def _create_client(config):
    return msal.ConfidentialClientApplication(**config["client"]["init"])


def _initiate_auth_code_flow(client, scopes, redirect_uri, state, **kwargs):
    auth_code_flow = client.initiate_auth_code_flow(
        scopes=scopes, redirect_uri=redirect_uri, state=state, **kwargs
    )

    return auth_code_flow
