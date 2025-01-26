"""
OIDC/OAuth2 backend module.
"""
import datetime
import logging
from urllib.parse import urlparse

from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient, backchannel_logout
from idpyoidc.server.user_authn.authn_context import UNSPECIFIED
from idpyoidc.message.oidc.session import BackChannelLogoutRequest, LogoutToken

from satosa.backends.base import BackendModule
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
import satosa.logging_util as lu
from ..exception import SATOSAAuthenticationError
from ..exception import SATOSAError
from ..response import Redirect, Response


UTC = datetime.timezone.utc
logger = logging.getLogger(__name__)


class IdpyOIDCBackend(BackendModule):
    """
    Backend module for OIDC and OAuth 2.0, can be directly used.
    """

    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name, storage,
                 logout_callback_func):
        """
        OIDC backend module.
        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param config: Configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin
        :param storage: storage to hold the backend session information
        :param logout_callback_func: Callback should be called by the module after the logout
        in the backend is done. This may trigger log out flow for all the frontends associated
        with the backend session

        :type auth_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str]]
        :type base_url: str
        :type name: str
        :type storage: satosa.storage.Storage
        :type logout_callback_func: str
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        """
        super().__init__(auth_callback_func, internal_attributes, base_url, name, storage, logout_callback_func)
        self.client = StandAloneClient(config=config["client"], client_type="oidc")
        self.client.do_provider_info()
        self.client.do_client_registration()

        _redirect_uris = self.client.context.claims.get_usage('redirect_uris')
        if not _redirect_uris:
            raise SATOSAError("Missing path in redirect uri")
        self.redirect_path = urlparse(_redirect_uris[0]).path

        front_channel_logout_uri = config["client"].get('front_channel_logout_uri')
        self.front_channel_logout_path = urlparse(front_channel_logout_uri).path if front_channel_logout_uri else None
        back_channel_logout_uri = config["client"].get('back_channel_logout_uri')
        self.back_channel_logout_path = urlparse(back_channel_logout_uri).path if back_channel_logout_uri else None

    def start_auth(self, context, internal_request):
        """
        See super class method satosa.backends.base#start_auth

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Redirect
        """
        login_url = self.client.init_authorization()
        return Redirect(login_url)

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        url_map = [(f"^{self.redirect_path.lstrip('/')}$", self.response_endpoint)]
        if self.front_channel_logout_path:
            url_map.append((f"^{self.front_channel_logout_path.lstrip('/')}$", self.front_channel_logout_endpoint))
        if self.back_channel_logout_path:
            url_map.append((f"^{self.back_channel_logout_path.lstrip('/')}$", self.back_channel_logout_endpoint))
        return url_map

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

        _info = self.client.finalize(context.request)
        self._check_error_response(_info, context)
        userinfo = _info.get('userinfo')
        id_token = _info.get('id_token')

        if not id_token and not userinfo:
            msg = "No id_token or userinfo, nothing to do.."
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, "No user info available.")

        all_user_claims = dict(list(userinfo.items()) + list(id_token.items()))
        msg = "UserInfo: {}".format(all_user_claims)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        internal_resp = self._translate_response(all_user_claims, _info["issuer"])
        sid = all_user_claims.get("sid")
        if sid:
            backend_session_id = self.storage.store_backend_session(sid, _info["issuer"])
            internal_resp.backend_session_id = backend_session_id
        return self.auth_callback_func(context, internal_resp)

    def front_channel_logout_endpoint(self, context):
        """
        Handles the front channel logout request from the OP.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :return:
        """

        logger.info(lu.LOG_FMT.format(id=lu.get_session_id(context.state),
                                      message="Received front-channel logout request: {}".format(context.request)))
        sid = context.request.get("sid")
        issuer = context.request.get("iss")
        backend_session = self.storage.get_backend_session(sid, issuer)

        if backend_session:
            internal_req = InternalData(
                backend_session_id=backend_session["id"],
                issuer=backend_session["issuer"]
            )
            return self.logout_callback_func(context, internal_req)
        else:
            return Response()

    def back_channel_logout_endpoint(self, context):
        """
        Handles the back channel logout request from the OP.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :return:
        """
        logger.info(lu.LOG_FMT.format(id=lu.get_session_id(context.state),
                                      message="Received back-channel logout request: {}".format(context.request)))

        if not context.request.get("logout_token"):
            logger.warning(lu.LOG_FMT.format(id=lu.get_session_id(context.state),
                                             message="back-channel logout request is received without logout token"))
            return Response(message="Missing logout token", status="400")
        else:
            back_channel_logout_request = BackChannelLogoutRequest(
                logout_token=context.request["logout_token"]).to_urlencoded()

            if self._verify_logout_token(context, back_channel_logout_request):
                logout_token = LogoutToken().from_jwt(context.request["logout_token"], None)
                sid = logout_token.get("sid")
                issuer = logout_token.get("iss")
                backend_session = self.storage.get_backend_session(sid, issuer)

                if backend_session:
                    internal_req = InternalData(
                        backend_session_id=backend_session["id"],
                        issuer=backend_session["issuer"]
                    )
                    return self.logout_callback_func(context, internal_req)
                else:
                    return Response(message="Invalid sid", status="400")
            else:
                return Response(message="Logout token verification failed", status="400")

    def _verify_logout_token(self, context, back_channel_logout_request):
        try:
            logger.debug(lu.LOG_FMT.format(id=lu.get_session_id(context.state),
                                           message="Starting logout token verification"))
            backchannel_logout(self.client, back_channel_logout_request)
            return True
        except Exception as e:
            logger.warning(lu.LOG_FMT.format(id=lu.get_session_id(context.state),
                                             message="Logout token verification failed"), e)
        return False

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
        timestamp_epoch = (
            response.get("auth_time")
            or response.get("iat")
            or int(datetime.datetime.now(UTC).timestamp())
        )
        timestamp_dt = datetime.datetime.fromtimestamp(timestamp_epoch, UTC)
        timestamp_iso = timestamp_dt.isoformat().replace("+00:00", "Z")
        auth_class_ref = response.get("acr") or response.get("amr") or UNSPECIFIED
        auth_info = AuthenticationInformation(auth_class_ref, timestamp_iso, issuer)

        internal_resp = InternalData(auth_info=auth_info)
        internal_resp.attributes = self.converter.to_internal("openid", response)
        internal_resp.subject_id = response["sub"]
        return internal_resp

    def _check_error_response(self, response, context):
        """
        Check if the response is an error response.
        :param response: the response from finalize()
        :type response: oic.oic.message
        :raise SATOSAAuthenticationError: if the response is an OAuth error response
        """
        if "error" in response:
            msg = "{name} error: {error} {description}".format(
                name=type(response).__name__,
                error=response["error"],
                description=response.get("error_description", ""),
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            raise SATOSAAuthenticationError(context.state, "Access denied")
