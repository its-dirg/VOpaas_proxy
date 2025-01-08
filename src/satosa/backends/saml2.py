"""
A saml2 backend module for the satosa proxy
"""
import copy
import functools
import json
import logging
import warnings as _warnings
from base64 import urlsafe_b64encode
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.extension.mdui import NAMESPACE as UI_NAMESPACE
from saml2.metadata import create_metadata_string
from saml2.authn_context import requested_authn_context
from saml2.samlp import RequesterID
from saml2.samlp import Scoping
from saml2.saml import NameID

import satosa.logging_util as lu
import satosa.util as util
from satosa.base import SAMLBaseModule
from satosa.base import SAMLEIDASBaseModule
from satosa.base import STATE_KEY as STATE_KEY_BASE
from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import LogoutInformation
from satosa.internal import InternalData
from satosa.exception import SATOSAAuthenticationError
from satosa.exception import SATOSAMissingStateError
from satosa.exception import SATOSAAuthenticationFlowError
from satosa.exception import SATOSAUnknownError
from satosa.response import SeeOther, Response
from satosa.saml_util import make_saml_response
from satosa.metadata_creation.description import (
    MetadataDescription, OrganizationDesc, ContactPersonDesc, UIInfoDesc
)
from satosa.backends.base import BackendModule


logger = logging.getLogger(__name__)


def get_memorized_idp(context, config, force_authn):
    memorized_idp = (
        config.get(SAMLBackend.KEY_MEMORIZE_IDP)
        and context.state.get(Context.KEY_MEMORIZED_IDP)
    )
    use_when_force_authn = config.get(
        SAMLBackend.KEY_USE_MEMORIZED_IDP_WHEN_FORCE_AUTHN
    )
    value = (not force_authn or use_when_force_authn) and memorized_idp
    return value


def get_force_authn(context, config, sp_config):
    """
    Return the force_authn value.

    The value comes from one of three place:
    - the configuration of the backend
    - the context, as it came through in the AuthnRequest handled by the frontend.
      note: the frontend should have been set to mirror the force_authn value.
    - the cookie, as it has been stored by the proxy on a redirect to the DS
      note: the frontend should have been set to mirror the force_authn value.

    The value is either "true" or None
    """
    mirror = config.get(SAMLBackend.KEY_MIRROR_FORCE_AUTHN)
    from_state = mirror and context.state.get(Context.KEY_FORCE_AUTHN)
    from_context = (
        mirror and context.get_decoration(Context.KEY_FORCE_AUTHN) in ["true", "1"]
    )
    from_config = sp_config.getattr("force_authn", "sp")
    is_set = str(from_state or from_context or from_config).lower() == "true"
    value = "true" if is_set else None
    return value


class SAMLBackend(BackendModule, SAMLBaseModule):
    """
    A saml2 backend module (acting as a SP).
    """
    KEY_DISCO_SRV = 'disco_srv'
    KEY_SAML_DISCOVERY_SERVICE_URL = 'saml_discovery_service_url'
    KEY_SAML_DISCOVERY_SERVICE_POLICY = 'saml_discovery_service_policy'
    KEY_SP_CONFIG = 'sp_config'
    KEY_SEND_REQUESTER_ID = 'send_requester_id'
    KEY_MIRROR_FORCE_AUTHN = 'mirror_force_authn'
    KEY_IS_PASSIVE = 'is_passive'
    KEY_MEMORIZE_IDP = 'memorize_idp'
    KEY_USE_MEMORIZED_IDP_WHEN_FORCE_AUTHN = 'use_memorized_idp_when_force_authn'

    VALUE_ACR_COMPARISON_DEFAULT = 'exact'

    def __init__(self, outgoing, internal_attributes, config, base_url, name, logout):
        """
        :type outgoing:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[str, dict[str, list[str] | str]]
        :type config: dict[str, Any]
        :type base_url: str
        :type name: str
        :type logout:

        :param outgoing: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Internal attribute map
        :param config: The module config
        :param base_url: base url of the service
        :param name: name of the plugin
        :param logout: Logout callback
        """
        super().__init__(outgoing, internal_attributes, base_url, name, logout)
        self.config = self.init_config(config)

        self.discosrv = config.get(SAMLBackend.KEY_DISCO_SRV)
        self.encryption_keys = []
        self.outstanding_queries = {}
        self.idp_blacklist_file = config.get('idp_blacklist_file', None)

        sp_config = SPConfig().load(copy.deepcopy(config[SAMLBackend.KEY_SP_CONFIG]))

        # if encryption_keypairs is defined, use those keys for decryption
        # else, if key_file and cert_file are defined, use them for decryption
        # otherwise, do not use any decryption key.
        # ensure the choice is reflected back in the configuration.
        sp_conf_encryption_keypairs = sp_config.getattr('encryption_keypairs', '')
        sp_conf_key_file = sp_config.getattr('key_file', '')
        sp_conf_cert_file = sp_config.getattr('cert_file', '')
        sp_keypairs = (
            sp_conf_encryption_keypairs
            if sp_conf_encryption_keypairs
            else [{'key_file': sp_conf_key_file, 'cert_file': sp_conf_cert_file}]
            if sp_conf_key_file and sp_conf_cert_file
            else []
        )
        sp_config.setattr('', 'encryption_keypairs', sp_keypairs)

        # load the encryption keys
        key_file_paths = [pair['key_file'] for pair in sp_keypairs]
        for p in key_file_paths:
            with open(p) as key_file:
                self.encryption_keys.append(key_file.read())

        # finally, initialize the client object
        self.sp = Saml2Client(sp_config)

    def get_idp_entity_id(self, context):
        """
        :type context: satosa.context.Context
        :rtype: str | None

        :param context: The current context
        :return: the entity_id of the idp or None
        """

        idps = self.sp.metadata.identity_providers()
        only_one_idp_in_metadata = (
            "mdq" not in self.config["sp_config"]["metadata"]
            and len(idps) == 1
        )

        only_idp = only_one_idp_in_metadata and idps[0]
        target_entity_id = context.get_decoration(Context.KEY_TARGET_ENTITYID)
        force_authn = get_force_authn(context, self.config, self.sp.config)
        memorized_idp = get_memorized_idp(context, self.config, force_authn)
        entity_id = only_idp or target_entity_id or memorized_idp or None

        msg = {
            "message": "Selected IdP",
            "only_one": only_idp,
            "target_entity_id": target_entity_id,
            "force_authn": force_authn,
            "memorized_idp": memorized_idp,
            "entity_id": entity_id,
        }
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.info(logline)
        return entity_id

    def start_auth(self, context, internal_req):
        """
        See super class method satosa.backends.base.BackendModule#start_auth

        :type context: satosa.context.Context
        :type internal_req: satosa.internal.InternalData
        :rtype: satosa.response.Response
        """

        entity_id = self.get_idp_entity_id(context)
        if entity_id is None:
            # since context is not passed to disco_query
            # keep the information in the state cookie
            context.state[Context.KEY_FORCE_AUTHN] = get_force_authn(
                context, self.config, self.sp.config
            )
            return self.disco_query(context)

        return self.authn_request(context, entity_id)

    def start_logout(self, context, internal_req, internal_authn_resp):
        """
        See super class method satosa.backends.base.BackendModule#start_logout

        :type context: satosa.context.Context
        :type internal_req: satosa.internal.InternalData
        :rtype: satosa.response.Response
        """

        if internal_authn_resp is None:
            message = "Session Information Deleted"
            status = "500 FAILED"
            return Response(message=message, status=status)
        entity_id = internal_authn_resp["auth_info"]["issuer"]
        if entity_id is None:
            message = "Logout Failed"
            status = "500 FAILED"
            return Response(message=message, status=status)
        return self.logout_request(context, entity_id, internal_authn_resp)

    def disco_query(self, context):
        """
        Makes a request to the discovery server

        :type context: satosa.context.Context
        :type internal_req: satosa.internal.InternalData
        :rtype: satosa.response.SeeOther

        :param context: The current context
        :param internal_req: The request
        :return: Response
        """
        endpoints = self.sp.config.getattr("endpoints", "sp")
        return_url = endpoints["discovery_response"][0][0]

        disco_url = (
            context.get_decoration(SAMLBackend.KEY_SAML_DISCOVERY_SERVICE_URL)
            or self.discosrv
        )
        disco_policy = context.get_decoration(
            SAMLBackend.KEY_SAML_DISCOVERY_SERVICE_POLICY
        )

        args = {"return": return_url}
        if disco_policy:
            args["policy"] = disco_policy

        loc = self.sp.create_discovery_service_request(
            disco_url, self.sp.config.entityid, **args
        )

        msg = {
            "message": "Sending user to the discovery service",
            "disco_url": loc
        }
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.info(logline)

        return SeeOther(loc)

    def construct_requested_authn_context(self, entity_id, *, target_accr=None):
        acr_entry = (
            target_accr
            or util.get_dict_defaults(self.acr_mapping or {}, entity_id)
        )
        if not acr_entry:
            return None

        if type(acr_entry) is not dict:
            acr_entry = {
                "class_ref": acr_entry,
                "comparison": self.VALUE_ACR_COMPARISON_DEFAULT,
            }

        authn_context = requested_authn_context(
            acr_entry['class_ref'], comparison=acr_entry.get(
                'comparison', self.VALUE_ACR_COMPARISON_DEFAULT
            )
        )

        return authn_context

    def authn_request(self, context, entity_id):
        """
        Do an authorization request on idp with given entity id.
        This is the start of the authorization.

        :type context: satosa.context.Context
        :type entity_id: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param entity_id: Target IDP entity id
        :return: response to the user agent
        """

        # If IDP blacklisting is enabled and the selected IDP is blacklisted,
        # stop here
        if self.idp_blacklist_file:
            with open(self.idp_blacklist_file) as blacklist_file:
                blacklist_array = json.load(blacklist_file)['blacklist']
                if entity_id in blacklist_array:
                    msg = {
                        "message": "AuthnRequest Failed",
                        "error": f"Selected IdP with EntityID {entity_id} is blacklisted for this backend",
                    }
                    logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                    logger.info(logline)
                    raise SATOSAAuthenticationError(context.state, msg)

        kwargs = {}
        target_accr = context.state.get(Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF)
        authn_context = self.construct_requested_authn_context(entity_id, target_accr=target_accr)
        if authn_context:
            kwargs["requested_authn_context"] = authn_context
        if self.config.get(SAMLBackend.KEY_MIRROR_FORCE_AUTHN):
            kwargs["force_authn"] = get_force_authn(
                context, self.config, self.sp.config
            )
        if self.config.get(SAMLBackend.KEY_SEND_REQUESTER_ID):
            requester = context.state.state_dict[STATE_KEY_BASE]['requester']
            kwargs["scoping"] = Scoping(requester_id=[RequesterID(text=requester)])
        if self.config.get(SAMLBackend.KEY_IS_PASSIVE):
            kwargs["is_passive"] = "true"

        try:
            acs_endp, response_binding = self._get_acs(context)
            relay_state = util.rndstr()
            req_id, binding, http_info = self.sp.prepare_for_negotiated_authenticate(
                entityid=entity_id,
                assertion_consumer_service_url=acs_endp,
                response_binding=response_binding,
                relay_state=relay_state,
                **kwargs,
            )
        except Exception as e:
            msg = {
                "message": "AuthnRequest Failed",
                "error": f"Failed to construct the AuthnRequest for state: {e}",
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            raise SATOSAAuthenticationError(context.state, msg) from e

        if self.sp.config.getattr('allow_unsolicited', 'sp') is False:
            if req_id in self.outstanding_queries:
                msg = {
                    "message": "AuthnRequest Failed",
                    "error": f"Request with duplicate id {req_id}",
                }
                logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                logger.info(logline)
                raise SATOSAAuthenticationError(context.state, msg)
            self.outstanding_queries[req_id] = req_id

        context.state[self.name] = {"relay_state": relay_state}
        return make_saml_response(binding, http_info)

    def _get_acs(self, context):
        """
        Select the AssertionConsumerServiceURL and binding.

        :param context: The current context
        :type context: satosa.context.Context
        :return: Selected ACS URL and binding
        :rtype: tuple(str, str)
        """
        acs_strategy = self.config.get("acs_selection_strategy", "use_first_acs")
        if acs_strategy == "use_first_acs":
            acs_strategy_fn = self._use_first_acs
        elif acs_strategy == "prefer_matching_host":
            acs_strategy_fn = self._prefer_matching_host
        else:
            msg = "Invalid value for '{}' ({}). Using the first ACS instead".format(
                "acs_selection_strategy", acs_strategy
            )
            logger.error(msg)
            acs_strategy_fn = self._use_first_acs
        return acs_strategy_fn(context)

    def _use_first_acs(self, context):
        return self.sp.config.getattr("endpoints", "sp")["assertion_consumer_service"][
            0
        ]

    def _prefer_matching_host(self, context):
        acs_config = self.sp.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"
        ]
        try:
            hostname = context.http_headers["HTTP_HOST"]
            for acs, binding in acs_config:
                parsed_acs = urlparse(acs)
                if hostname == parsed_acs.netloc:
                    msg = "Selected ACS '{}' based on the request".format(acs)
                    logline = lu.LOG_FMT.format(
                        id=lu.get_session_id(context.state), message=msg
                    )
                    logger.debug(logline)
                    return acs, binding
        except (TypeError, KeyError):
            pass

        msg = "Can't find an ACS URL to this hostname ({}), selecting the first one".format(
            context.http_headers.get("HTTP_HOST", "") if context.http_headers else ""
        )
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        return self._use_first_acs(context)

    def authn_response(self, context, binding):
        """
        Endpoint for the idp response
        :type context: satosa.context,Context
        :type binding: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param binding: The saml binding type
        :return: response
        """

        if self.name not in context.state:
            """
            If we end up here, it means that the user returns to the proxy
            without the SATOSA session cookie. This can happen at least in the
            following cases:
            - the user deleted the cookie from the browser
            - the browser of the user blocked the cookie
            - the user has completed an authentication flow, the cookie has
              been removed by SATOSA and then the user used the back button
              of their browser and resend the authentication response, but
              without the SATOSA session cookie
            """
            msg = {
                "message": "Authentication failed",
                "error": "Received AuthN response without a SATOSA session cookie",
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            raise SATOSAMissingStateError(msg)

        samlresponse = context.request.get("SAMLResponse")
        if not samlresponse:
            msg = {
                "message": "Authentication failed",
                "error": "SAML Response not found in context.request",
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        try:
            authn_response = self.sp.parse_authn_request_response(
                samlresponse, binding, outstanding=self.outstanding_queries
            )
        except Exception as e:
            msg = {
                "message": "Authentication failed",
                "error": f"Failed to parse Authn response: {e}",
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline, exc_info=True)
            logger.info(logline)
            raise SATOSAAuthenticationError(context.state, msg) from e

        if self.sp.config.getattr('allow_unsolicited', 'sp') is False:
            req_id = authn_response.in_response_to
            if req_id not in self.outstanding_queries:
                msg = {
                    "message": "Authentication failed",
                    "error": f"No corresponding request with id: {req_id}",
                }
                logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
                logger.info(logline)
                raise SATOSAAuthenticationError(context.state, msg)
            del self.outstanding_queries[req_id]

        # check if the relay_state matches the cookie state
        if context.state[self.name].get("relay_state") != context.request["RelayState"]:
            msg = {
                "message": "Authentication failed",
                "error": "Response state query param did not match relay state for request",
            }
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        context.decorate(Context.KEY_METADATA_STORE, self.sp.metadata)
        if self.config.get(SAMLBackend.KEY_MEMORIZE_IDP):
            issuer = authn_response.response.issuer.text.strip()
            context.state[Context.KEY_MEMORIZED_IDP] = issuer
        context.state.pop(Context.KEY_FORCE_AUTHN, None)
        return self.auth_callback_func(context, self._translate_response(authn_response, context.state))

    def logout_request(self, context, entity_id, internal_authn_resp):
        """
        Perform Logout request on idp with given entity_id.
        This is the start of single logout.

        :type context: satosa.context.Context
        :type entity_id: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param entity_id: Target IDP entity id
        :return: response to the user agent
        """
        try:
            binding, destination = self.sp.pick_binding(
                    "single_logout_service", None, "idpsso", entity_id=entity_id
            )
            msg = "binding: {}, destination: {}".format(binding, destination)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)

            slo_endp, response_binding = self.sp.config.getattr("endpoints", "sp")["single_logout_service"][0]
            name_id_format = self.sp.config.getattr("name_id_format", "sp")
            name_id = internal_authn_resp["subject_id"]
            name_id = NameID(format=name_id_format, text=name_id)
            session_indexes = internal_authn_resp["auth_info"]["session_index"]
            sign = self.sp.config.getattr("logout_requests_signed", "sp")
            req_id, req = self.sp.create_logout_request(
                destination, issuer_entity_id=entity_id, name_id=name_id,
                session_indexes=session_indexes, sign=sign
            )
            msg = "req_id: {}, req: {}".format(req_id, req)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            relay_state = util.rndstr()
            ht_args = self.sp.apply_binding(binding, "%s" % req, destination, relay_state=relay_state)
            msg = "ht_args: {}".format(ht_args)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
        except Exception as exc:
            msg = "Failed to construct the LogoutRequest for state"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline, exc_info=True)
            status = "500 FAILED"
            return Response(message=msg, status=status)
        return make_saml_response(binding, ht_args)

    def logout_response(self, context, binding):
        """
        Endpoint for the idp logout response

        :type context: satosa.context.Context
        :type binding: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param binding: SAML binding type
        :return Response
        """
        if not context.request.get("SAMLResponse"):
            msg = "Missing Response for state"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            raise SATOSAUnknownError(context.state, "Missing Response")

        try:
            logout_response = self.sp.parse_logout_request_response(
                    context.request["SAMLResponse"], binding)
        except Exception as err:
            msg = "Failed to parse logout response for state"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline, exc_info=True)
            message = "Logout Failed"
            status = "500 FAILED"
            return Response(message=message, status=status)
        return self.logout_callback_func(context)

    def disco_response(self, context):
        """
        Endpoint for the discovery server response

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response
        """
        info = context.request
        state = context.state

        if 'SATOSA_BASE' not in state:
            raise SATOSAAuthenticationFlowError("Discovery response without AuthN request")

        entity_id = info.get("entityID")
        msg = {
            "message": "Received response from the discovery service",
            "entity_id": entity_id,
        }
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.info(logline)
        if not entity_id:
            raise SATOSAAuthenticationError(state, msg) from err

        return self.authn_request(context, entity_id)

    def _translate_response(self, response, state):
        """
        Translates a saml authorization response to an internal response

        :type response: saml2.response.AuthnResponse
        :rtype: satosa.internal.InternalData
        :param response: The saml authorization response
        :return: A translated internal response
        """

        # The response may have been encrypted by the IdP so if we have an
        # encryption key, try it.
        if self.encryption_keys:
            response.parse_assertion(keys=self.encryption_keys)

        issuer = response.response.issuer.text
        authn_context_ref, authenticating_authorities, authn_instant = next(
            iter(response.authn_info()), [None, None, None]
        )
        authenticating_authority = (
            authenticating_authorities[-1]
            if authenticating_authorities
            else None
        )
        session_indexes = []
        session_indexes.append(response.session_info()['session_index'])
        auth_info = AuthenticationInformation(
            auth_class_ref=authn_context_ref,
            timestamp=authn_instant,
            authority=authenticating_authority,
            issuer=issuer,
            session_index=session_indexes,
        )

        # The SAML response may not include a NameID.
        subject = response.get_subject()
        name_id = subject.text if subject else None
        name_id_format = subject.format if subject else None

        attributes = self.converter.to_internal(
            self.attribute_profile, response.ava,
        )

        internal_resp = InternalData(
            auth_info=auth_info,
            attributes=attributes,
            subject_type=name_id_format,
            subject_id=name_id,
        )

        msg = "backend received attributes: {}".format(response.ava)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
        logger.debug(logline)

        msg = {
            "message": "Attributes received by the backend",
            "issuer": issuer,
            "attributes": " ".join(list(response.ava.keys()))
        }
        if name_id_format:
            msg['name_id'] = name_id_format
        logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
        logger.info(logline)

        return internal_resp

    def _translate_logout_response(self, response, state):
        timestamp = response.response.issue_instant
        issuer = response.response.issuer.text

        status = {
            "status_code": response.response.status.status_code.value,
        }

        logout_info = LogoutInformation(
            timestamp=timestamp,
            issuer=issuer,
            status=status
        )

        msg = "logout response content"
        logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
        logger.debug(logline)
        return logout_info

    def _metadata_endpoint(self, context):
        """
        Endpoint for retrieving the backend metadata
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response with metadata
        """
        msg = "Sending metadata response for entityId = {}".format(self.sp.config.entityid)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        metadata_string = create_metadata_string(
            configfile=None, config=self.sp.config, valid=4
        ).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def register_endpoints(self):
        """
        See super class method satosa.backends.base.BackendModule#register_endpoints
        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]
        """
        url_map = []
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(("^%s$" % parsed_endp.path[1:], functools.partial(self.authn_response, binding=binding)))
            if binding == BINDING_HTTP_REDIRECT:
                msg = " ".join(
                    [
                        "AssertionConsumerService endpoint with binding",
                        BINDING_HTTP_REDIRECT,
                        "is not recommended.",
                        "Quoting section 4.1.2 of",
                        "'Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0':",
                        "The HTTP Redirect binding MUST NOT be used,",
                        "as the response will typically exceed the URL length",
                        "permitted by most user agents.",
                    ]
                )
                _warnings.warn(msg, UserWarning)

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                parsed_endp = urlparse(endp)
                url_map.append(
                    ("^%s$" % parsed_endp.path[1:], self.disco_response))

        if self.expose_entityid_endpoint():
            logger.debug("Exposing backend entity endpoint = {}".format(self.sp.config.entityid))
            parsed_entity_id = urlparse(self.sp.config.entityid)
            url_map.append(("^{0}".format(parsed_entity_id.path[1:]),
                            self._metadata_endpoint))

        if self.enable_metadata_reload():
            url_map.append(
                ("^%s/%s$" % (self.name, "reload-metadata"), self._reload_metadata))

        for endp, binding in sp_endpoints["single_logout_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(("^%s$" % parsed_endp.path[1:],
                functools.partial(self.logout_response, binding=binding)))

        return url_map

    def _reload_metadata(self, context):
        """
        Reload SAML metadata
        """
        logger.debug("Reloading metadata")
        res = self.sp.reload_metadata(
            copy.deepcopy(self.config[SAMLBackend.KEY_SP_CONFIG]['metadata'])
        )
        message = "Metadata reload %s" % ("OK" if res else "failed")
        status = "200 OK" if res else "500 FAILED"
        return Response(message=message, status=status)

    def get_metadata_desc(self):
        """
        See super class satosa.backends.backend_base.BackendModule#get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        entity_descriptions = []

        idp_entities = self.sp.metadata.with_descriptor("idpsso")
        for entity_id, entity in idp_entities.items():
            description = MetadataDescription(urlsafe_b64encode(entity_id.encode("utf-8")).decode("utf-8"))

            # Add organization info
            try:
                organization_info = entity["organization"]
            except KeyError:
                pass
            else:
                organization = OrganizationDesc()
                for name_info in organization_info.get("organization_name", []):
                    organization.add_name(name_info["text"], name_info["lang"])
                for display_name_info in organization_info.get("organization_display_name", []):
                    organization.add_display_name(display_name_info["text"], display_name_info["lang"])
                for url_info in organization_info.get("organization_url", []):
                    organization.add_url(url_info["text"], url_info["lang"])
                description.organization = organization

            # Add contact person info
            try:
                contact_persons = entity["contact_person"]
            except KeyError:
                pass
            else:
                for person in contact_persons:
                    person_desc = ContactPersonDesc()
                    person_desc.contact_type = person.get("contact_type")
                    for address in person.get('email_address', []):
                        person_desc.add_email_address(address["text"])
                    if "given_name" in person:
                        person_desc.given_name = person["given_name"]["text"]
                    if "sur_name" in person:
                        person_desc.sur_name = person["sur_name"]["text"]

                    description.add_contact_person(person_desc)

            # Add UI info
            ui_info = self.sp.metadata.extension(entity_id, "idpsso_descriptor", "{}&UIInfo".format(UI_NAMESPACE))
            if ui_info:
                ui_info = ui_info[0]
                ui_info_desc = UIInfoDesc()
                for desc in ui_info.get("description", []):
                    ui_info_desc.add_description(desc["text"], desc["lang"])
                for name in ui_info.get("display_name", []):
                    ui_info_desc.add_display_name(name["text"], name["lang"])
                for logo in ui_info.get("logo", []):
                    ui_info_desc.add_logo(logo["text"], logo["width"], logo["height"], logo.get("lang"))
                for keywords in ui_info.get("keywords", []):
                    ui_info_desc.add_keywords(keywords.get("text", []), keywords.get("lang"))
                for information_url in ui_info.get("information_url", []):
                    ui_info_desc.add_information_url(information_url.get("text"), information_url.get("lang"))
                for privacy_statement_url in ui_info.get("privacy_statement_url", []):
                    ui_info_desc.add_privacy_statement_url(
                        privacy_statement_url.get("text"), privacy_statement_url.get("lang")
                    )
                description.ui_info = ui_info_desc

            entity_descriptions.append(description)
        return entity_descriptions


class SAMLEIDASBackend(SAMLBackend, SAMLEIDASBaseModule):
    """
    A saml2 eidas backend module (acting as a SP).
    """
    VALUE_ACR_CLASS_REF_DEFAULT = 'http://eidas.europa.eu/LoA/high'
    VALUE_ACR_COMPARISON_DEFAULT = 'minimum'

    def init_config(self, config):
        config = super().init_config(config)

        spec_eidas_sp = {
            'acr_mapping': {
                "": {
                    'class_ref': self.VALUE_ACR_CLASS_REF_DEFAULT,
                    'comparison': self.VALUE_ACR_COMPARISON_DEFAULT,
                },
            },
            'sp_config.service.sp.authn_requests_signed': True,
            'sp_config.service.sp.want_response_signed': True,
            'sp_config.service.sp.allow_unsolicited': False,
            'sp_config.service.sp.force_authn': True,
            'sp_config.service.sp.hide_assertion_consumer_service': True,
            'sp_config.service.sp.sp_type': ['private', 'public'],
            'sp_config.service.sp.sp_type_in_metadata': [True, False],
        }

        return util.check_set_dict_defaults(config, spec_eidas_sp)
