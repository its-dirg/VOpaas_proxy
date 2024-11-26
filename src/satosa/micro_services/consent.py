"""
A consent module for the satosa proxy
"""
import hashlib
import json
import logging
from base64 import urlsafe_b64encode

import requests
from jwkest.jwk import RSAKey
from jwkest.jwk import rsa_load
from jwkest.jws import JWS
from requests.exceptions import ConnectionError

import satosa.logging_util as lu
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.util import join_paths


logger = logging.getLogger(__name__)

STATE_KEY = "CONSENT"


class UnexpectedResponseError(Exception):
    pass


class Consent(ResponseMicroService):
    """
    Module for handling consent. Uses an external consent service
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "consent"
        self.api_url = config["api_url"]
        self.redirect_url = config["redirect_url"]
        self.locked_attr = None
        if "user_id_to_attr" in internal_attributes:
            self.locked_attr = internal_attributes["user_id_to_attr"]

        self.signing_key = RSAKey(key=rsa_load(config["sign_key"]), use="sig", alg="RS256")
        self.endpoint = "/handle_consent"
        logger.info("Consent flow is active")

    def _handle_consent_response(self, context):
        """
        Endpoint for handling consent service response
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        consent_state = context.state[STATE_KEY]
        saved_resp = consent_state["internal_resp"]
        internal_response = InternalData.from_dict(saved_resp)

        hash_id = self._get_consent_id(internal_response.requester, internal_response.subject_id,
                                       internal_response.attributes)

        try:
            consent_attributes = self._verify_consent(hash_id)
        except ConnectionError as e:
            msg = "Consent service is not reachable, no consent given."
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, exc_info=e)
            # Send an internal_response without any attributes
            consent_attributes = None

        if consent_attributes is None:
            msg = "Consent was NOT given"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            # If consent was not given, then don't send any attributes
            consent_attributes = []
        else:
            msg = "Consent was given"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)

        internal_response.attributes = self._filter_attributes(internal_response.attributes, consent_attributes)
        return self._end_consent(context, internal_response)

    def _approve_new_consent(self, context, internal_response, id_hash):
        context.state[STATE_KEY]["internal_resp"] = internal_response.to_dict()

        consent_args = {
            "attr": internal_response.attributes,
            "id": id_hash,
            "redirect_endpoint": "%s/consent%s" % (self.base_url, self.endpoint),
            "requester": internal_response.requester,
            "requester_name": internal_response.requester_name,
        }
        if self.locked_attr:
            consent_args["locked_attrs"] = [self.locked_attr]
        if 'requester_logo' in context.state[STATE_KEY]:
             consent_args["requester_logo"] = context.state[STATE_KEY]['requester_logo']
        try:
            ticket = self._consent_registration(consent_args)
        except (ConnectionError, UnexpectedResponseError) as e:
            msg = "Consent request failed, no consent given: {}".format(str(e))
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            # Send an internal_response without any attributes
            internal_response.attributes = {}
            return self._end_consent(context, internal_response)

        consent_redirect = "%s/%s" % (self.redirect_url, ticket)
        return Redirect(consent_redirect)

    def process(self, context, internal_response):
        """
        Manage consent and attribute filtering

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: response context
        :param internal_response: the response
        :return: response
        """
        context.state[STATE_KEY] = context.state.get(STATE_KEY, {})
        id_hash = self._get_consent_id(
            internal_response.requester,
            internal_response.subject_id,
            internal_response.attributes,
        )

        try:
            # Check if consent is already given
            consent_attributes = self._verify_consent(id_hash)
        except requests.exceptions.ConnectionError as e:
            msg = "Consent service is not reachable, no consent is given."
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, exc_info=e)
            # Send an internal_response without any attributes
            internal_response.attributes = {}
            return self._end_consent(context, internal_response)

        # Previous consent was given
        if consent_attributes is not None:
            msg = "Previous consent was given"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            internal_response.attributes = self._filter_attributes(internal_response.attributes, consent_attributes)
            return self._end_consent(context, internal_response)

        # No previous consent, request consent by user
        return self._approve_new_consent(context, internal_response, id_hash)

    def _filter_attributes(self, attributes, filter):
        return {k: v for k, v in attributes.items() if k in filter}

    def _get_consent_id(self, requester, user_id, filtered_attr):
        """
        Get a hashed id based on requester, user id and filtered attributes

        :type requester: str
        :type user_id: str
        :type filtered_attr: dict[str, str]

        :param requester: The calling requester
        :param user_id: The authorized user id
        :param filtered_attr: a list containing all attributes to be sent
        :return: an id
        """

        filtered_attr_key_list = sorted(filtered_attr.keys())
        hash_str = ""
        for key in filtered_attr_key_list:
            _hash_value = "".join(sorted(filtered_attr[key]))
            hash_str += key + _hash_value
        id_string = "%s%s%s" % (requester, user_id, hash_str)
        return urlsafe_b64encode(hashlib.sha512(id_string.encode("utf-8")).hexdigest().encode("utf-8")).decode("utf-8")

    def _consent_registration(self, consent_args):
        """
        Register a request at the consent service

        :type consent_args: dict
        :rtype: str

        :param consent_args: All necessary parameters for the consent request
        :return: Ticket received from the consent service
        """
        jws = JWS(json.dumps(consent_args), alg=self.signing_key.alg).sign_compact([self.signing_key])
        request = "{}/creq/{}".format(self.api_url, jws)
        res = requests.get(request)

        if res.status_code != 200:
            raise UnexpectedResponseError("Consent service error: %s %s", res.status_code, res.text)

        return res.text

    def _verify_consent(self, consent_id):
        """
        Connects to the consent service using the REST api and checks if the user has given consent

        :type consent_id: str
        :rtype: Optional[List[str]]

        :param consent_id: An id associated to the authenticated user, the calling requester and
        attributes to be sent.
        :return: list attributes given which have been approved by user consent
        """
        request = "{}/verify/{}".format(self.api_url, consent_id)
        res = requests.get(request)

        if res.status_code == 200:
            return json.loads(res.text)

        return None

    def _end_consent(self, context, internal_response):
        """
        Clear the state for consent and end the consent step

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: response context
        :param internal_response: the response
        :return: response
        """
        context.state.pop(STATE_KEY, None)
        return super().process(context, internal_response)

    def register_endpoints(self):
        """
        Register consent module endpoints

        :rtype: list[(srt, (satosa.context.Context) -> Any)]

        :return: A list of endpoints bound to a function
        """
        return [
            (
                "^{}$".format(
                    join_paths(self.base_path, "consent", self.endpoint)
                ),
                self._handle_consent_response,
            )
        ]
