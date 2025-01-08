"""
The SATOSA main module
"""
import json
import logging
import uuid

from saml2.s_utils import UnknownSystemEntity

from satosa import util
from satosa.response import BadRequest
from satosa.response import NotFound
from satosa.response import Redirect
from .context import Context
from .exception import SATOSAError, SATOSAAuthenticationError, SATOSAUnknownError
from .plugin_loader import load_backends, load_frontends
from .plugin_loader import load_request_microservices, load_response_microservices
from .plugin_loader import load_database
from .routing import ModuleRouter, SATOSANoBoundEndpointError
from .state import cookie_to_state, SATOSAStateError, State, state_to_cookie
from .exception import SATOSAAuthenticationError
from .exception import SATOSAAuthenticationFlowError
from .exception import SATOSABadRequestError
from .exception import SATOSAError
from .exception import SATOSAMissingStateError
from .exception import SATOSANoBoundEndpointError
from .exception import SATOSAUnknownError
from .exception import SATOSAStateError
from .plugin_loader import load_backends
from .plugin_loader import load_frontends
from .plugin_loader import load_request_microservices
from .plugin_loader import load_response_microservices
from .routing import ModuleRouter
from .state import State
from .state import cookie_to_state
from .state import state_to_cookie

import satosa.logging_util as lu


logger = logging.getLogger(__name__)

STATE_KEY = "SATOSA_BASE"


class SATOSABase(object):
    """
    Base class for a satosa proxy server.
    Does not contain any server parts.
    """

    def __init__(self, config):
        """
        Creates a satosa proxy base

        :type config: satosa.satosa_config.SATOSAConfig
        :param config: satosa proxy config
        """
        self.config = config

        logger.info("Loading backend modules...")
        backends = load_backends(self.config, self._auth_resp_callback_func,
                                 self.config["INTERNAL_ATTRIBUTES"],
                                 self._logout_resp_callback_func
                                 )
        logger.info("Loading frontend modules...")
        frontends = load_frontends(self.config, self._auth_req_callback_func,
                                   self.config["INTERNAL_ATTRIBUTES"],
                                   self._logout_req_callback_func
                                   )

        self.response_micro_services = []
        self.request_micro_services = []
        logger.info("Loading micro services...")
        if "MICRO_SERVICES" in self.config:
            self.request_micro_services.extend(load_request_microservices(
                self.config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
                self.config["MICRO_SERVICES"],
                self.config["INTERNAL_ATTRIBUTES"],
                self.config["BASE"]))
            self._link_micro_services(self.request_micro_services, self._auth_req_finish)

            self.response_micro_services.extend(
                load_response_microservices(self.config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
                                            self.config["MICRO_SERVICES"],
                                            self.config["INTERNAL_ATTRIBUTES"],
                                            self.config["BASE"]))
            self._link_micro_services(self.response_micro_services, self._auth_resp_finish)

        load_db = self.config.get("LOGOUT_ENABLED", False)
        if load_db:
            logger.info("Loading database...")
            self.db = load_database(self.config)

        self.module_router = ModuleRouter(frontends, backends,
                                          self.request_micro_services + self.response_micro_services)

    def _link_micro_services(self, micro_services, finisher):
        if not micro_services:
            return

        for i in range(len(micro_services) - 1):
            micro_services[i].next = micro_services[i + 1].process

        micro_services[-1].next = finisher

    def _auth_req_callback_func(self, context, internal_request):
        """
        This function is called by a frontend module when an authorization request has been
        processed.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_request: request processed by the frontend

        :return: response
        """
        state = context.state
        state[STATE_KEY] = {"requester": internal_request.requester}

        msg = "Requesting provider: {}".format(internal_request.requester)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
        logger.info(logline)

        if self.request_micro_services:
            return self.request_micro_services[0].process(context, internal_request)

        return self._auth_req_finish(context, internal_request)

    def _logout_req_callback_func(self, context, internal_request):
        """
        This function is called by a frontend module when a logout request has been processed.

        :type context: satosa.context.Context
        :typr internal_request:
        :rtype:

        :param context: The request context
        :param internal_request: request processed by the frontend
        :return Response
        """
        state = context.state
        state[STATE_KEY] = {"requester": internal_request.requester}
        msg = "Requesting provider: {}".format(internal_request.requester)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
        logger.info(logline)
        return self._logout_req_finish(context, internal_request)

    def _auth_req_finish(self, context, internal_request):
        backend = self.module_router.backend_routing(context)
        context.request = None
        return backend.start_auth(context, internal_request)

    def _logout_req_finish(self, context, internal_request):
        backend = self.module_router.backend_routing(context)
        context.request = None
        if hasattr(self, "db"):
            internal_authn_resp = self.db.get_authn_resp(context.state)
            self.db.delete_session(context.state)
        else:
            internal_authn_resp = None
            context.state.delete = self.config.get("CONTEXT_STATE_DELETE", True)
        return backend.start_logout(context, internal_request, internal_authn_resp)

    def _auth_resp_finish(self, context, internal_response):
        user_id_to_attr = self.config["INTERNAL_ATTRIBUTES"].get("user_id_to_attr", None)
        if user_id_to_attr:
            internal_response.attributes[user_id_to_attr] = [internal_response.subject_id]

        # remove all session state unless CONTEXT_STATE_DELETE is False
        context.request = None
        if hasattr(self, "db"):
            self.db.store_authn_resp(context.state, internal_response)
            self.db.get_authn_resp(context.state)
        else:
            context.state.delete = self.config.get("CONTEXT_STATE_DELETE", True)

        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_authn_response(context, internal_response)

    def _logout_resp_finish(self, context):
        context.request = None

        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_logout_response(context)

    def _auth_resp_callback_func(self, context, internal_response):
        """
        This function is called by a backend module when the authorization is
        complete.

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_response: The authentication response
        :return: response
        """

        context.request = None
        internal_response.requester = context.state[STATE_KEY]["requester"]

        # If configured construct the user id from attribute values.
        if "user_id_from_attrs" in self.config["INTERNAL_ATTRIBUTES"]:
            subject_id = [
                "".join(internal_response.attributes[attr]) for attr in
                self.config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"]
            ]
            internal_response.subject_id = "".join(subject_id)

        if self.response_micro_services:
            return self.response_micro_services[0].process(
                context, internal_response)

        return self._auth_resp_finish(context, internal_response)

    def _logout_resp_callback_func(self, context):
        """
        This function is called by a backend module when logout is complete

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.LogoutInformation
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_response: The logout response
        """
        context.request = None
        context.state["ROUTER"] = "idp"
        return self._logout_resp_finish(context)

    def _handle_satosa_authentication_error(self, error):
        """
        Sends a response to the requester about the error

        :type error: satosa.exception.SATOSAAuthenticationError
        :rtype: satosa.response.Response

        :param error: The exception
        :return: response
        """
        context = Context()
        context.state = error.state
        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_backend_error(error)

    def _run_bound_endpoint(self, context, spec):
        """

        :type context: satosa.context.Context
        :type spec: ((satosa.context.Context, Any) -> satosa.response.Response, Any) |
        (satosa.context.Context) -> satosa.response.Response

        :param context: The request context
        :param spec: bound endpoint function
        :return: response
        """
        try:
            return spec(context)
        except SATOSAAuthenticationError as error:
            error.error_id = uuid.uuid4().urn
            state = json.dumps(error.state.state_dict, indent=4)
            msg = "ERROR_ID [{err_id}]\nSTATE:\n{state}".format(
                err_id=error.error_id, state=state
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, exc_info=True)
            return self._handle_satosa_authentication_error(error)

    def _load_state(self, context):
        """
        Load state from cookie to the context

        :type context: satosa.context.Context
        :param context: Session context
        """
        try:
            state = cookie_to_state(
                context.cookie,
                self.config["COOKIE_STATE_NAME"],
                self.config["STATE_ENCRYPTION_KEY"],
            )
        except SATOSAStateError:
            state = State()
        finally:
            context.state = state
            msg = f"Loaded state {state} from cookie {context.cookie}"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

    def _save_state(self, resp, context):
        """
        Saves a state from context to cookie

        :type resp: satosa.response.Response
        :type context: satosa.context.Context

        :param resp: The response
        :param context: Session context
        """

        cookie_name = self.config["COOKIE_STATE_NAME"]
        cookie = state_to_cookie(
            context.state,
            name=cookie_name,
            path="/",
            encryption_key=self.config["STATE_ENCRYPTION_KEY"],
            secure=self.config.get("COOKIE_SECURE"),
            httponly=self.config.get("COOKIE_HTTPONLY"),
            samesite=self.config.get("COOKIE_SAMESITE"),
            max_age=self.config.get("COOKIE_MAX_AGE"),
        )
        resp.headers = [
            (name, value)
            for (name, value) in resp.headers
            if name != "Set-Cookie"
            or not value.startswith(f"{cookie_name}=")
        ]
        resp.headers.append(tuple(cookie.output().split(": ", 1)))

    def run(self, context):
        """
        Runs the satosa proxy with the given context.

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The request context
        :return: response
        """
        try:
            self._load_state(context)
            spec = self.module_router.endpoint_routing(context)
            resp = self._run_bound_endpoint(context, spec)
            self._save_state(resp, context)
        except SATOSABadRequestError as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "Bad Request",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                redirect_url = f"{generic_error_url}?errorid={error_id}"
                return Redirect(generic_error_url)
            return BadRequest(e.error)
        except SATOSAMissingStateError as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "Missing SATOSA State",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                redirect_url = f"{generic_error_url}?errorid={error_id}"
                return Redirect(generic_error_url)
            raise
        except SATOSAAuthenticationFlowError as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "SATOSA Authentication Flow Error",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                redirect_url = f"{generic_error_url}?errorid={error_id}"
                return Redirect(generic_error_url)
            raise
        except SATOSANoBoundEndpointError as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "URL-path is not bound to any endpoint function",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                redirect_url = f"{generic_error_url}?errorid={error_id}"
                return Redirect(generic_error_url)
            return NotFound("The Service or Identity Provider you requested could not be found.")
        except SATOSAError as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "Uncaught SATOSA error",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                redirect_url = f"{generic_error_url}?errorid={error_id}"
                return Redirect(generic_error_url)
            raise
        except UnknownSystemEntity as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "Configuration error: unknown system entity",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                redirect_url = f"{generic_error_url}?errorid={error_id}"
                return Redirect(generic_error_url)
            raise
        except Exception as e:
            error_id = uuid.uuid4().urn
            msg = {
                "message": "Uncaught exception",
                "error": str(e),
                "error_id": error_id,
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            generic_error_url = self.config.get("ERROR_URL")
            if generic_error_url:
                return Redirect(generic_error_url)
            raise SATOSAUnknownError("Unknown error") from e
        else:
            return resp


class SAMLBaseModule(object):
    KEY_ENTITYID_ENDPOINT = 'entityid_endpoint'
    KEY_ENABLE_METADATA_RELOAD = 'enable_metadata_reload'
    KEY_ATTRIBUTE_PROFILE = 'attribute_profile'
    KEY_ACR_MAPPING = 'acr_mapping'
    VALUE_ATTRIBUTE_PROFILE_DEFAULT = 'saml'

    def init_config(self, config):
        self.attribute_profile = config.get(
            self.KEY_ATTRIBUTE_PROFILE,
            self.VALUE_ATTRIBUTE_PROFILE_DEFAULT)
        self.acr_mapping = config.get(self.KEY_ACR_MAPPING)
        return config

    def expose_entityid_endpoint(self):
        value = self.config.get(self.KEY_ENTITYID_ENDPOINT, False)
        return bool(value)

    def enable_metadata_reload(self):
        """
        Check whether metadata reload has been enabled in config

        return: bool
        """
        value = self.config.get(self.KEY_ENABLE_METADATA_RELOAD, False)
        return bool(value)


class SAMLEIDASBaseModule(SAMLBaseModule):
    VALUE_ATTRIBUTE_PROFILE_DEFAULT = 'eidas'

    def init_config(self, config):
        config = super().init_config(config)

        spec_eidas = {
            'entityid_endpoint': True,
        }

        return util.check_set_dict_defaults(config, spec_eidas)
