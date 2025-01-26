"""
A OpenID Connect frontend module for the satosa proxy
"""

import json
import logging
import uuid
import requests
import time
from collections import defaultdict
from urllib.parse import urlencode, urlparse

from jwkest.jwk import rsa_load, RSAKey

from oic.oic import scope2claims
from oic.oic.message import AuthorizationRequest, LogoutToken
from oic.oic.message import AuthorizationErrorResponse
from oic.oic.message import TokenErrorResponse
from oic.oic.message import UserInfoErrorResponse
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint

from pyop.access_token import AccessToken
from pyop.authz_state import AuthorizationState
from pyop.exceptions import InvalidAuthenticationRequest
from pyop.exceptions import InvalidClientRegistrationRequest
from pyop.exceptions import InvalidClientAuthentication
from pyop.exceptions import OAuthError
from pyop.exceptions import BearerTokenError
from pyop.exceptions import InvalidAccessToken
from pyop.provider import Provider
from pyop.storage import StorageBase
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo
from pyop.util import should_fragment_encode

from .base import FrontendModule
from ..response import BadRequest, Created
from ..response import SeeOther, Response
from ..response import Unauthorized
from ..util import rndstr

import satosa.logging_util as lu
from satosa.internal import InternalData


logger = logging.getLogger(__name__)


class MirrorPublicSubjectIdentifierFactory(HashBasedSubjectIdentifierFactory):
    def create_public_identifier(self, user_id):
        return user_id


class OpenIDConnectFrontend(FrontendModule):
    """
    A OpenID Connect frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf, base_url, name, storage,
                 logout_callback):
        _validate_config(conf)
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name, storage)

        self.config = conf
        provider_config = self.config["provider"]
        provider_config["issuer"] = base_url

        self.signing_key = RSAKey(
            key=rsa_load(self.config["signing_key_path"]),
            use="sig",
            alg="RS256",
            kid=self.config.get("signing_key_id", ""),
        )

        db_uri = self.config.get("db_uri")
        self.stateless = db_uri and StorageBase.type(db_uri) == "stateless"
        self.user_db = (
            StorageBase.from_uri(db_uri, db_name="satosa", collection="authz_codes")
            if db_uri and not self.stateless
            else {}
        )

        sub_hash_salt = self.config.get("sub_hash_salt", rndstr(16))
        mirror_public = self.config.get("sub_mirror_public", False)
        authz_state = _init_authorization_state(
            provider_config, db_uri, sub_hash_salt, mirror_public
        )

        client_db_uri = self.config.get("client_db_uri")
        cdb_file = self.config.get("client_db_path")
        if client_db_uri:
            self.cdb = StorageBase.from_uri(
                client_db_uri, db_name="satosa", collection="clients", ttl=None
            )
        elif cdb_file:
            with open(cdb_file) as f:
                self.cdb = json.loads(f.read())
        else:
            self.cdb = {}

        self.endpoint_baseurl = "{}/{}".format(self.base_url, self.name)
        self.provider = _create_provider(
            provider_config,
            self.endpoint_baseurl,
            self.internal_attributes,
            self.signing_key,
            authz_state,
            self.user_db,
            self.cdb,
        )

    def _get_extra_id_token_claims(self, user_id, client_id):
        if "extra_id_token_claims" in self.config["provider"]:
            config = self.config["provider"]["extra_id_token_claims"].get(client_id, [])
            if type(config) is list and len(config) > 0:
                requested_claims = {k: None for k in config}
                return self.provider.userinfo.get_claims_for(user_id, requested_claims)
        return {}

    def handle_authn_response(self, context, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype oic.utils.http_util.Response
        """

        auth_req = self._get_authn_request_from_state(context.state)

        claims = self.converter.from_internal("openid", internal_resp.attributes)
        # Filter unset claims
        claims = {k: v for k, v in claims.items() if v}
        self.user_db[internal_resp.subject_id] = dict(
            combine_claim_values(claims.items())
        )
        auth_resp = self.provider.authorize(
            auth_req,
            internal_resp.subject_id,
            extra_id_token_claims=lambda user_id, client_id:
                self._get_extra_id_token_claims(user_id, client_id),
        )

        if self.stateless:
            del self.user_db[internal_resp.subject_id]

        del context.state[self.name]
        http_response = auth_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req))
        frontend_sid = context.state.session_id
        internal_resp.frontend_sid = frontend_sid

        self.storage.store_frontend_session(
            self.name,
            internal_resp.requester,
            internal_resp.subject_id,
            frontend_sid)

        return SeeOther(http_response)

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        auth_req = self._get_authn_request_from_state(exception.state)
        # If the client sent us a state parameter, we should reflect it back according to the spec
        if 'state' in auth_req:
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message,
                                                    state=auth_req['state'])
        else:
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message)
        msg = exception.message
        logline = lu.LOG_FMT.format(id=lu.get_session_id(exception.state), message=msg)
        logger.debug(logline)
        return SeeOther(error_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req)))

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        backend_name = None
        if len(backend_names) != 1:
            # only supports one backend since there currently is no way to publish multiple authorization endpoints
            # in configuration information and there is no other standard way of authorization_endpoint discovery
            # similar to SAML entity discovery
            # this can be circumvented with a custom RequestMicroService which handles the routing based on something
            # in the authentication request
            logline = (
                "More than one backend is configured, "
                "make sure to provide a custom routing micro service "
                "to determine which backend should be used per request."
            )
            logger.warning(logline)
        else:
            backend_name = backend_names[0]

        provider_config = ("^.well-known/openid-configuration$", self.provider_config)
        jwks_uri = ("^{}/jwks$".format(self.name), self.jwks)

        if backend_name:
            # if there is only one backend, include its name in the path so the default routing can work
            auth_endpoint = "{}/{}/{}/{}".format(self.base_url, backend_name, self.name, AuthorizationEndpoint.url)
            self.provider.configuration_information["authorization_endpoint"] = auth_endpoint
            auth_path = urlparse(auth_endpoint).path.lstrip("/")
        else:
            auth_path = "{}/{}".format(self.name, AuthorizationEndpoint.url)

        authentication = ("^{}$".format(auth_path), self.handle_authn_request)
        url_map = [provider_config, jwks_uri, authentication]

        if any("code" in v for v in self.provider.configuration_information["response_types_supported"]):
            self.provider.configuration_information["token_endpoint"] = "{}/{}".format(
                self.endpoint_baseurl, TokenEndpoint.url
            )
            token_endpoint = (
                "^{}/{}".format(self.name, TokenEndpoint.url), self.token_endpoint
            )
            url_map.append(token_endpoint)

            self.provider.configuration_information["userinfo_endpoint"] = (
                "{}/{}".format(self.endpoint_baseurl, UserinfoEndpoint.url)
            )
            userinfo_endpoint = (
                "^{}/{}".format(self.name, UserinfoEndpoint.url), self.userinfo_endpoint
            )
            url_map.append(userinfo_endpoint)

        if "registration_endpoint" in self.provider.configuration_information:
            client_registration = (
                "^{}/{}".format(self.name, RegistrationEndpoint.url),
                self.client_registration,
            )
            url_map.append(client_registration)

        return url_map

    def _get_authn_request_from_state(self, state):
        """
        Extract the clietns request stoed in the SATOSA state.
        :type state: satosa.state.State
        :rtype: oic.oic.message.AuthorizationRequest

        :param state: the current state
        :return: the parsed authentication request
        """
        return AuthorizationRequest().deserialize(state[self.name]["oidc_request"])

    def client_registration(self, context):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        try:
            resp = self.provider.handle_client_registration_request(json.dumps(context.request))
            return Created(resp.to_json(), content="application/json")
        except InvalidClientRegistrationRequest as e:
            return BadRequest(e.to_json(), content="application/json")

    def provider_config(self, context):
        """
        Construct the provider configuration information (served at /.well-known/openid-configuration).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return Response(self.provider.provider_configuration.to_json(), content="application/json")

    def _get_approved_attributes(self, provider_supported_claims, authn_req):
        requested_claims = list(
            scope2claims(
                authn_req["scope"], self.config["provider"].get("extra_scopes")
            ).keys()
        )
        if "claims" in authn_req:
            for k in ["id_token", "userinfo"]:
                if k in authn_req["claims"]:
                    requested_claims.extend(authn_req["claims"][k].keys())
        return set(provider_supported_claims).intersection(set(requested_claims))

    def _handle_authn_request(self, context):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: satosa.internal.InternalData

        :param context: the current context
        :return: the internal request
        """
        request = urlencode(context.request)
        msg = "Authn req from client: {}".format(request)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        try:
            authn_req = self.provider.parse_authentication_request(request)
        except InvalidAuthenticationRequest as e:
            msg = "Error in authn req: {}".format(str(e))
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            error_url = e.to_error_url()

            if error_url:
                return SeeOther(error_url)
            else:
                return BadRequest("Something went wrong: {}".format(str(e)))

        client_id = authn_req["client_id"]
        context.state[self.name] = {"oidc_request": request}
        subject_type = self.provider.clients[client_id].get("subject_type", "pairwise")
        client_name = self.provider.clients[client_id].get("client_name")
        if client_name:
            # TODO should process client names for all languages, see OIDC Registration, Section 2.1
            requester_name = [{"lang": "en", "text": client_name}]
        else:
            requester_name = None
        internal_req = InternalData(
            subject_type=subject_type,
            requester=client_id,
            requester_name=requester_name,
        )

        internal_req.attributes = self.converter.to_internal_filter(
            "openid", self._get_approved_attributes(self.provider.configuration_information["claims_supported"],
                                                    authn_req))
        return internal_req

    def handle_authn_request(self, context):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        internal_req = self._handle_authn_request(context)
        if not isinstance(internal_req, InternalData):
            return internal_req
        return self.auth_req_callback_func(context, internal_req)

    def jwks(self, context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return Response(json.dumps(self.provider.jwks), content="application/json")

    def token_endpoint(self, context):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        headers = {"Authorization": context.request_authorization}
        try:
            response = self.provider.handle_token_request(
                urlencode(context.request),
                headers,
                lambda user_id, client_id: self._get_extra_id_token_claims(user_id, client_id))
            return Response(response.to_json(), content="application/json")
        except InvalidClientAuthentication as e:
            logline = "invalid client authentication at token endpoint"
            logger.debug(logline, exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
            response = Unauthorized(error_resp.to_json(), headers=[("WWW-Authenticate", "Basic")],
                                    content="application/json")
            return response
        except OAuthError as e:
            logline = "invalid request: {}".format(str(e))
            logger.debug(logline, exc_info=True)
            error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
            return BadRequest(error_resp.to_json(), content="application/json")

    def userinfo_endpoint(self, context):
        headers = {"Authorization": context.request_authorization}

        try:
            response = self.provider.handle_userinfo_request(
                request=urlencode(context.request),
                http_headers=headers,
            )
            return Response(response.to_json(), content="application/json")
        except (BearerTokenError, InvalidAccessToken) as e:
            error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
            response = Unauthorized(error_resp.to_json(), headers=[("WWW-Authenticate", AccessToken.BEARER_TOKEN_TYPE)],
                                    content="application/json")
            return response

    def start_logout_from_backend(self, context, internal_request):
        """
        Performs the back-channel logout for the RP
        :param context: the current context
        :param internal_request: internalData containing the frontend sid
        :return: whether the back-channel logout was successful or not

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype bool
        """
        logout_status = True
        session = self.storage.get_frontend_session(internal_request.frontend_sid)
        client = self.cdb[session.get("requester")]

        if client.get("back_channel_logout_uri"):
            try:
                logout_token = LogoutToken(iss=self.base_url,
                                           sub=session.get("subject_id"),
                                           aud=session.get("requester"),
                                           iat=int(time.time()),
                                           jti=str(uuid.uuid4()),
                                           events={"http://schemas.openid.net/event/backchannel-logout": {}},
                                           sid=internal_request.frontend_sid
                                           )

                logout_token_str = logout_token.to_jwt([self.signing_key], "RS256")
                logger.debug('signed logout_token {} using alg={}'.format(logout_token_str, "RS256"))
                resp = requests.post(client.get("back_channel_logout_uri"), json={"logout_token": logout_token_str}, verify=False)

                if resp.status_code == 200:
                    self.storage.delete_frontend_session(internal_request.frontend_sid)
                    msg = "RP with client id '{}' of the frontend name '{}' logged out successfully.".format(
                        session.get("requester"), self.name)
                    logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                    logger.info(logline)
                else:
                    msg = "client {} could not log out successfully - received status code: {} and payload: {} " \
                          "from the client.".format(
                            session.get("requester"),
                            resp.status_code,
                            resp.content)

                    logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                    logger.warning(logline)
                    logout_status = False
            except Exception as e:
                msg = "client {} could not log out successfully - encountered error: {}".format(
                    session.get("requester"), e)
                logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                logger.warning(logline)
                logout_status = False
        else:
            logger.info(
                lu.LOG_FMT.format(id=lu.get_session_id(context.state),
                                  message="client {} does not support logout").format(session.get("requester")))
        return logout_status


def _validate_config(config):
    """
    Validates that all necessary config parameters are specified.
    :type config: dict[str, dict[str, Any] | str]
    :param config: the module config
    """
    if config is None:
        raise ValueError("OIDCFrontend configuration can't be 'None'.")

    for k in {"signing_key_path", "provider"}:
        if k not in config:
            raise ValueError("Missing configuration parameter '{}' for OpenID Connect frontend.".format(k))

    if "signing_key_id" in config and type(config["signing_key_id"]) is not str:
        raise ValueError(
            "The configuration parameter 'signing_key_id' is not defined as a string for OpenID Connect frontend.")


def _create_provider(
    provider_config,
    endpoint_baseurl,
    internal_attributes,
    signing_key,
    authz_state,
    user_db,
    cdb,
):
    response_types_supported = provider_config.get("response_types_supported", ["id_token"])
    subject_types_supported = provider_config.get("subject_types_supported", ["pairwise"])
    scopes_supported = provider_config.get("scopes_supported", ["openid"])
    extra_scopes = provider_config.get("extra_scopes")
    capabilities = {
        "issuer": provider_config["issuer"],
        "authorization_endpoint": "{}/{}".format(endpoint_baseurl, AuthorizationEndpoint.url),
        "jwks_uri": "{}/jwks".format(endpoint_baseurl),
        "response_types_supported": response_types_supported,
        "id_token_signing_alg_values_supported": [signing_key.alg],
        "response_modes_supported": ["fragment", "query"],
        "subject_types_supported": subject_types_supported,
        "claim_types_supported": ["normal"],
        "claims_parameter_supported": True,
        "claims_supported": [
            attribute_map["openid"][0]
            for attribute_map in internal_attributes["attributes"].values()
            if "openid" in attribute_map
        ],
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
        "scopes_supported": scopes_supported
    }

    if 'code' in response_types_supported:
        capabilities["token_endpoint"] = "{}/{}".format(
            endpoint_baseurl, TokenEndpoint.url
        )

    if provider_config.get("client_registration_supported", False):
        capabilities["registration_endpoint"] = "{}/{}".format(
            endpoint_baseurl, RegistrationEndpoint.url
        )

    provider = Provider(
        signing_key,
        capabilities,
        authz_state,
        cdb,
        Userinfo(user_db),
        extra_scopes=extra_scopes,
        id_token_lifetime=provider_config.get("id_token_lifetime", 3600),
    )
    return provider


def _init_authorization_state(
    provider_config, db_uri, sub_hash_salt, mirror_public=False
):
    if db_uri:
        authz_code_db = StorageBase.from_uri(
            db_uri,
            db_name="satosa",
            collection="authz_codes",
            ttl=provider_config.get("authorization_code_lifetime", 600),
        )
        access_token_db = StorageBase.from_uri(
            db_uri,
            db_name="satosa",
            collection="access_tokens",
            ttl=provider_config.get("access_token_lifetime", 3600),
        )
        refresh_token_db = StorageBase.from_uri(
            db_uri,
            db_name="satosa",
            collection="refresh_tokens",
            ttl=provider_config.get("refresh_token_lifetime", None),
        )
        sub_db = StorageBase.from_uri(
            db_uri, db_name="satosa", collection="subject_identifiers", ttl=None
        )
    else:
        authz_code_db = None
        access_token_db = None
        refresh_token_db = None
        sub_db = None

    token_lifetimes = {
        k: provider_config[k]
        for k in [
            "authorization_code_lifetime",
            "access_token_lifetime",
            "refresh_token_lifetime",
            "refresh_token_threshold",
        ]
        if k in provider_config
    }

    subject_id_factory = (
        MirrorPublicSubjectIdentifierFactory(sub_hash_salt)
        if mirror_public
        else HashBasedSubjectIdentifierFactory(sub_hash_salt)
    )
    return AuthorizationState(
        subject_id_factory,
        authz_code_db,
        access_token_db,
        refresh_token_db,
        sub_db,
        **token_lifetimes,
    )


def combine_return_input(values):
    return values


def combine_select_first_value(values):
    return values[0]


def combine_join_by_space(values):
    return " ".join(values)


combine_values_by_claim = defaultdict(
    lambda: combine_return_input,
    {
        "sub": combine_select_first_value,
        "name": combine_select_first_value,
        "given_name": combine_join_by_space,
        "family_name": combine_join_by_space,
        "middle_name": combine_join_by_space,
        "nickname": combine_select_first_value,
        "preferred_username": combine_select_first_value,
        "profile": combine_select_first_value,
        "picture": combine_select_first_value,
        "website": combine_select_first_value,
        "email": combine_select_first_value,
        "email_verified": combine_select_first_value,
        "gender": combine_select_first_value,
        "birthdate": combine_select_first_value,
        "zoneinfo": combine_select_first_value,
        "locale": combine_select_first_value,
        "phone_number": combine_select_first_value,
        "phone_number_verified": combine_select_first_value,
        "address": combine_select_first_value,
        "updated_at": combine_select_first_value,
    },
)


def combine_claim_values(claim_items):
    claims = (
        (name, combine_values_by_claim[name](values))
        for name, values in claim_items
    )
    return claims
