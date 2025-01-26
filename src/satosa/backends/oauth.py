"""
OAuth 2 backends for SATOSA.
"""
import json
import logging
from base64 import urlsafe_b64encode

import requests

from oic.oauth2.consumer import Consumer, stateID
from oic.oauth2.message import AuthorizationResponse
from oic.utils.authn.authn_context import UNSPECIFIED

import satosa.logging_util as lu
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.exception import SATOSAAuthenticationError
from satosa.response import Redirect
from satosa.util import rndstr
from satosa.metadata_creation.description import (
    OrganizationDesc, UIInfoDesc, ContactPersonDesc, MetadataDescription
)
from satosa.backends.base import BackendModule


logger = logging.getLogger(__name__)


class _OAuthBackend(BackendModule):
    """
    Backend module for OAuth 2.0, should not be directly used.
    See satosa.backends.oauth.FacebookBackend.
    """

    def __init__(self, outgoing, internal_attributes, config, base_url, name, external_type, user_id_attr,
                 storage, logout_callback_func):
        """
        :param outgoing: Callback should be called by the module after the authorization in the
        backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param config: Configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin
        :param external_type: The name for this module in the internal attributes.

        :type outgoing:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str]]
        :type base_url: str
        :type name: str
        :type external_type: str
        """
        super().__init__(outgoing, internal_attributes, base_url, name, storage, logout_callback_func)
        self.config = config
        self.redirect_url = "%s/%s" % (self.config["base_url"], self.config["authz_page"])
        self.external_type = external_type
        self.user_id_attr = user_id_attr
        self.consumer = Consumer(
            session_db=None,
            client_config=self.config["client_config"],
            server_info=self.config["server_info"],
            authz_page=self.config["authz_page"],
            response_type=self.config["response_type"])
        self.consumer.client_secret = self.config["client_secret"]

    def start_auth(self, context, internal_request, get_state=stateID):
        """
        See super class method satosa.backends.base#start_auth
        :param get_state: Generates a state to be used in the authentication call.

        :type get_state: Callable[[str, bytes], str]
        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Redirect
        """
        request_args = self.get_request_args(get_state=get_state)
        context.state[self.name] = {"state": request_args["state"]}
        cis = self.consumer.construct_AuthorizationRequest(request_args=request_args)
        return Redirect(cis.request(self.consumer.authorization_endpoint))

    def get_request_args(self, get_state=stateID):
        oauth_state = get_state(self.config["base_url"], rndstr().encode())
        request_args = {
            "redirect_uri": self.redirect_url,
            "state": oauth_state,
        }
        return request_args

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        return [("^%s$" % self.config["authz_page"], self._authn_response)]

    def _verify_state(self, resp, state_data, state):
        """
        Will verify the state and throw and error if the state is invalid.
        :type resp: AuthorizationResponse
        :type state_data: dict[str, str]
        :type state: satosa.state.State

        :param resp: The authorization response from the AS, created by pyoidc.
        :param state_data: The state data for this backend.
        :param state: The current state for the proxy and this backend.
        Only used for raising errors.
        """
        is_known_state = "state" in resp and "state" in state_data and resp["state"] == state_data["state"]
        if not is_known_state:
            received_state = resp.get("state", "")
            msg = "Missing or invalid state [{}] in response!".format(received_state)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
            logger.debug(logline)
            raise SATOSAAuthenticationError(state,
                                            "Missing or invalid state [%s] in response!" %
                                            received_state)

    def _authn_response(self, context):
        """
        Handles the authentication response from the AS.

        :type context: satosa.context.Context
        :rtype: satosa.response.Response
        :param context: The context in SATOSA
        :return: A SATOSA response. This method is only responsible to call the callback function
        which generates the Response object.
        """
        state_data = context.state[self.name]
        aresp = self.consumer.parse_response(AuthorizationResponse, info=json.dumps(context.request))
        self._verify_state(aresp, state_data, context.state)

        rargs = {"code": aresp["code"], "redirect_uri": self.redirect_url,
                 "state": state_data["state"]}

        atresp = self.consumer.do_access_token_request(request_args=rargs, state=aresp["state"])
        if "verify_accesstoken_state" not in self.config or self.config["verify_accesstoken_state"]:
            self._verify_state(atresp, state_data, context.state)

        user_info = self.user_information(atresp["access_token"])
        internal_response = InternalData(auth_info=self.auth_info(context.request))
        internal_response.attributes = self.converter.to_internal(self.external_type, user_info)
        internal_response.subject_id = user_info[self.user_id_attr]
        return self.auth_callback_func(context, internal_response)

    def auth_info(self, request):
        """
        Creates the SATOSA authentication information object.
        :type request: dict[str, str]
        :rtype: AuthenticationInformation

        :param request: The request parameters in the authentication response sent by the AS.
        :return: How, who and when the autentication took place.
        """
        raise NotImplementedError("Method 'auth_info' must be implemented in the subclass!")

    def user_information(self, access_token):
        """
        Will retrieve the user information data for the authenticated user.
        :type access_token: str
        :rtype: dict[str, str]

        :param access_token: The access token to be used to retrieve the data.
        :return: Dictionary with attribute name as key and attribute value as value.
        """
        raise NotImplementedError("Method 'user_information' must be implemented in the subclass!")

    def get_metadata_desc(self):
        """
        See satosa.backends.oauth.get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        return get_metadata_desc_for_oauth_backend(
            self.config["server_info"]["authorization_endpoint"], self.config)


class FacebookBackend(_OAuthBackend):
    """
    Backend module for facebook.
    """

    """
    The default graph endpoint is for backward compatibility with previous versions of the
    Facebook backend in which the graph endpoint was hardcoded in the code.
    """
    DEFAULT_GRAPH_ENDPOINT = "https://graph.facebook.com/v2.5/me"

    def __init__(self, outgoing, internal_attributes, config, base_url, name, storage,
                 logout_callback_func):
        """
        Constructor.
        :param outgoing: Callback should be called by the module after the authorization in the
        backend is done.
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

        :type outgoing:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str] | str]
        :type base_url: str
        :type name: str
        :type storage: satosa.storage.Storage
        :type logout_callback_func: str
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        """
        config.setdefault("response_type", "code")
        config["verify_accesstoken_state"] = False
        super().__init__(outgoing, internal_attributes, config, base_url, name, "facebook", "id", storage,
                 logout_callback_func)

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
        """
        Creates the SATOSA authentication information object.
        :type request: dict[str, str]
        :rtype: AuthenticationInformation

        :param request: The request parameters in the authentication response sent by the AS.
        :return: How, who and when the autentication took place.
        """
        auth_info = AuthenticationInformation(UNSPECIFIED,
                                              None,
                                              self.config["server_info"]["authorization_endpoint"])
        return auth_info

    def user_information(self, access_token):
        """
        Will retrieve the user information data for the authenticated user.
        :type access_token: str
        :rtype: dict[str, str]

        :param access_token: The access token to be used to retrieve the data.
        :return: Dictionary with attribute name as key and attribute value as value.
        """
        payload = {"access_token": access_token}
        url = self.config["server_info"].get("graph_endpoint", self.DEFAULT_GRAPH_ENDPOINT)
        if self.config["fields"]:
            payload["fields"] = ",".join(self.config["fields"])
        resp = requests.get(url, params=payload)
        data = json.loads(resp.text)
        try:
            picture_url = data["picture"]["data"]["url"]
            data["picture"] = picture_url
        except KeyError:
            pass
        return data


def get_metadata_desc_for_oauth_backend(entity_id, config):
    """
    Returns a SAML metadata entity (IdP) descriptor for a configured OAuth/OpenID Connect Backend.
    :param entity_id: If entity_id is None, the id will be retrieved from the config
    :type entity_id: str
    :param config: The backend module config
    :type config: dict[str, Any]
    :return: metadata description
    :rtype: satosa.metadata_creation.description.MetadataDescription
    """
    metadata_description = []
    entity_id = urlsafe_b64encode(entity_id.encode("utf-8")).decode("utf-8")
    description = MetadataDescription(entity_id)

    if "entity_info" in config:
        entity_info = config["entity_info"]

        # Add contact person information
        for contact_person in entity_info.get("contact_person", []):
            person = ContactPersonDesc()
            if "contact_type" in contact_person:
                person.contact_type = contact_person["contact_type"]
            for address in contact_person.get("email_address", []):
                person.add_email_address(address)
            if "given_name" in contact_person:
                person.given_name = contact_person["given_name"]
            if "sur_name" in contact_person:
                person.sur_name = contact_person["sur_name"]

            description.add_contact_person(person)

        # Add organization information
        if "organization" in entity_info:
            organization_info = entity_info["organization"]
            organization = OrganizationDesc()

            for name_info in organization_info.get("organization_name", []):
                organization.add_name(name_info[0], name_info[1])
            for display_name_info in organization_info.get("organization_display_name", []):
                organization.add_display_name(display_name_info[0], display_name_info[1])
            for url_info in organization_info.get("organization_url", []):
                organization.add_url(url_info[0], url_info[1])

            description.organization = organization

        # Add ui information
        if "ui_info" in entity_info:
            ui_info = entity_info["ui_info"]
            ui_description = UIInfoDesc()
            for desc in ui_info.get("description", []):
                ui_description.add_description(desc[0], desc[1])
            for name in ui_info.get("display_name", []):
                ui_description.add_display_name(name[0], name[1])
            for logo in ui_info.get("logo", []):
                ui_description.add_logo(logo["image"], logo["width"], logo["height"], logo["lang"])
            for keywords in ui_info.get("keywords", []):
                ui_description.add_keywords(keywords.get("text", []), keywords.get("lang"))
            for information_url in ui_info.get("information_url", []):
                ui_description.add_information_url(information_url.get("text"), information_url.get("lang"))
            for privacy_statement_url in ui_info.get("privacy_statement_url", []):
                ui_description.add_information_url(
                    privacy_statement_url.get("text"), privacy_statement_url.get("lang")
                )

            description.ui_info = ui_description

    metadata_description.append(description)
    return metadata_description
