"""
Apple backend module.
"""
import logging
from .openid_connect import OpenIDConnectBackend, STATE_KEY
from oic.oauth2.message import Message
from oic.oic.message import AuthorizationResponse
import satosa.logging_util as lu
from ..exception import SATOSAAuthenticationError
import json
import requests


logger = logging.getLogger(__name__)


# https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple
class AppleBackend(OpenIDConnectBackend):
    """Sign in with Apple backend"""

    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name, storage,
                 logout_callback_func):
        """
        Sign in with Apple backend module.
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
        self.auth_callback_func = auth_callback_func
        self.config = config
        self.client = _create_client(
            config["provider_metadata"],
            config["client"]["client_metadata"],
            config["client"].get("verify_ssl", True),
        )
        if "scope" not in config["client"]["auth_req_params"]:
            config["auth_req_params"]["scope"] = "openid"
        if "response_type" not in config["client"]["auth_req_params"]:
            config["auth_req_params"]["response_type"] = "code"

    def start_auth(self, context, request_info):
        """
        See super class method satosa.backends.base#start_auth
        :type context: satosa.context.Context
        :type request_info: satosa.internal.InternalData
        """
        oidc_nonce = rndstr()
        oidc_state = rndstr()
        state_data = {NONCE_KEY: oidc_nonce, STATE_KEY: oidc_state}
        context.state[self.name] = state_data

        args = {
            "scope": self.config["client"]["auth_req_params"]["scope"],
            "response_type": self.config["client"]["auth_req_params"]["response_type"],
            "client_id": self.client.client_id,
            "redirect_uri": self.client.registration_response["redirect_uris"][0],
            "state": oidc_state,
            "nonce": oidc_nonce,
        }
        args.update(self.config["client"]["auth_req_params"])
        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(self.client.authorization_endpoint)
        return Redirect(login_url)

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        url_map = []
        redirect_path = urlparse(
            self.config["client"]["client_metadata"]["redirect_uris"][0]
        ).path
        if not redirect_path:
            raise SATOSAError("Missing path in redirect uri")

        url_map.append(("^%s$" % redirect_path.lstrip("/"), self.response_endpoint))
        return url_map

    def _verify_nonce(self, nonce, context):
        """
        Verify the received OIDC 'nonce' from the ID Token.
        :param nonce: OIDC nonce
        :type nonce: str
        :param context: current request context
        :type context: satosa.context.Context
        :raise SATOSAAuthenticationError: if the nonce is incorrect
        """
        backend_state = context.state[self.name]
        if nonce != backend_state[NONCE_KEY]:
            msg = "Missing or invalid nonce in authn response for state: {}".format(
                backend_state
            )
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(
                context.state, "Missing or invalid nonce in authn response"
            )

    def _get_tokens(self, authn_response, context):
        """
        :param authn_response: authentication response from OP
        :type authn_response: oic.oic.message.AuthorizationResponse
        :return: access token and ID Token claims
        :rtype: Tuple[Optional[str], Optional[Mapping[str, str]]]
        """
        if "code" in authn_response:
            # make token request
            # https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
            args = {
                "client_id": self.client.client_id,
                "client_secret": self.client.client_secret,
                "code": authn_response["code"],
                "grant_type": "authorization_code",
                "redirect_uri": self.client.registration_response["redirect_uris"][0],
            }

            token_resp = requests.post(
                "https://appleid.apple.com/auth/token",
                data=args,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ).json()

            logger.debug("apple response received")
            logger.debug(token_resp)

            self._check_error_response(token_resp, context)

            keyjar = self.client.keyjar
            id_token_claims = dict(
                Message().from_jwt(token_resp["id_token"], keyjar=keyjar)
            )

            return token_resp["access_token"], id_token_claims

        return authn_response.get("access_token"), authn_response.get("id_token")

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

        # Apple has no userinfo endpoint
        # but may send some user information via POST in the first request.
        #
        # References:
        # - https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
        # - https://developer.apple.com/documentation/sign_in_with_apple/namei
        try:
            userdata = context.request.get("user", "{}")
            userinfo = json.loads(userdata)
        except json.JSONDecodeError:
            userinfo = {}

        authn_resp = self.client.parse_response(
            AuthorizationResponse, info=context.request, sformat="dict"
        )
        if backend_state[STATE_KEY] != authn_resp["state"]:
            msg = "Missing or invalid state in authn response for state: {}".format(
                backend_state
            )
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(
                context.state, "Missing or invalid state in authn response"
            )

        self._check_error_response(authn_resp, context)
        access_token, id_token_claims = self._get_tokens(authn_resp, context)
        if not id_token_claims:
            id_token_claims = {}

        if not id_token_claims and not userinfo:
            msg = "No id_token or userinfo, nothing to do.."
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, "No user info available.")

        all_user_claims = dict(list(userinfo.items()) + list(id_token_claims.items()))

        # convert "string or Boolean" claims to actual booleans
        for bool_claim_name in ["email_verified", "is_private_email"]:
            if type(all_user_claims.get(bool_claim_name)) == str:
                all_user_claims[bool_claim_name] = (
                    True if all_user_claims[bool_claim_name] == "true" else False
                )

        msg = "UserInfo: {}".format(all_user_claims)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        internal_resp = self._translate_response(
            all_user_claims, self.client.authorization_endpoint
        )
        return self.auth_callback_func(context, internal_resp)
