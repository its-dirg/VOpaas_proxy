"""
An account linking module for the satosa proxy
"""
import json
import logging

import requests
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS

from satosa.internal import InternalData
from ..exception import SATOSAAuthenticationError
from ..micro_services.base import ResponseMicroService
from ..response import Redirect
from ..util import join_paths

import satosa.logging_util as lu
logger = logging.getLogger(__name__)


class AccountLinking(ResponseMicroService):
    """
    Module for handling account linking and recovery. Uses an external account linking service
    """

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        self.api_url = config["api_url"]
        self.redirect_url = config["redirect_url"]
        self.signing_key = RSAKey(key=rsa_load(config["sign_key"]), use="sig", alg="RS256")
        self.endpoint = "/handle_account_linking"
        self.id_to_attr = config.get("id_to_attr", None)
        logger.info("Account linking is active")

    def _handle_al_response(self, context):
        """
        Endpoint for handling account linking service response. When getting here
        user might have approved or rejected linking their account

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response
        """
        saved_state = context.state[self.name]
        internal_response = InternalData.from_dict(saved_state)

        #subject_id here is the linked id , not the facebook one, Figure out what to do
        status_code, message = self._get_uuid(context, internal_response.auth_info.issuer, internal_response.attributes['issuer_user_id'])

        if status_code == 200:
            msg = "issuer/id pair is linked in AL service"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            internal_response.subject_id = message
            if self.id_to_attr:
                internal_response.attributes[self.id_to_attr] = [message]

            del context.state[self.name]
            return super().process(context, internal_response)
        else:
            # User selected not to link their accounts, so the internal.response.subject_id is based on the
            # issuers id/sub which is fine
            msg = "User selected to not link their identity in AL service"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            del context.state[self.name]
            return super().process(context, internal_response)


    def process(self, context, internal_response):
        """
        Manage account linking and recovery

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context:
        :param internal_response:
        :return: response
        :
        """

        status_code, message = self._get_uuid(context, internal_response.auth_info.issuer, internal_response.subject_id)

        data = {
            "issuer": internal_response.auth_info.issuer,
            "redirect_endpoint": "%s/account_linking%s" % (self.base_url, self.endpoint)
        }

        # Store the issuer subject_id/sub because we'll need it in handle_al_response
        internal_response.attributes['issuer_user_id'] = internal_response.subject_id
        if status_code == 200:
            msg = "issuer/id pair is linked in AL service"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            internal_response.subject_id = message
            data['user_id'] = message
            if self.id_to_attr:
                internal_response.attributes[self.id_to_attr] = [message]
        else:
            msg = "issuer/id pair is not linked in AL service. Got a ticket"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)
            data['ticket'] = message
        jws = JWS(json.dumps(data), alg=self.signing_key.alg).sign_compact([self.signing_key])
        context.state[self.name] = internal_response.to_dict()
        return Redirect("%s/%s" % (self.redirect_url, jws))

    def _get_uuid(self, context, issuer, id):
        """
        Ask the account linking service for a uuid.
        If the given issuer/id pair is not linked, then the function will return a ticket.
        This ticket should be used for linking the issuer/id pair to the user account

        :type context: satosa.context.Context
        :type issuer: str
        :type id: str
        :rtype: (int, str)

        :param context: The current context
        :param issuer: the issuer used for authentication
        :param id: the given id
        :return: response status code and message
            (200, uuid) or (404, ticket)
        """
        data = {
            "idp": issuer,
            "id": id,
            "redirect_endpoint": "%s/account_linking%s" % (self.base_url, self.endpoint)
        }
        jws = JWS(json.dumps(data), alg=self.signing_key.alg).sign_compact([self.signing_key])

        try:
            request = "{}/get_id?jwt={}".format(self.api_url, jws)
            response = requests.get(request)
        except Exception as con_exc:
            msg = "Could not connect to account linking service"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.critical(logline)
            raise SATOSAAuthenticationError(context.state, msg) from con_exc

        if response.status_code not in [200, 404]:
            msg = "Got status code '{}' from account linking service".format(response.status_code)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.critical(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        return response.status_code, response.text

    def register_endpoints(self):
        """
        Register consent module endpoints

        :rtype: list[(srt, (satosa.context.Context) -> Any)]

        :return: A list of endpoints bound to a function
        """
        return [
            (
                "^{}$".format(
                    join_paths(self.base_path, "account_linking", self.endpoint)
                ),
                self._handle_al_response,
            )
        ]
