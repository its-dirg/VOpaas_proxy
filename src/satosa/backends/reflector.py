"""
A reflector backend module for the satosa proxy
"""
import base64
from datetime import datetime

from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.metadata_creation.description import MetadataDescription
from satosa.backends.base import BackendModule


class ReflectorBackend(BackendModule):
    """
    A reflector backend module
    """

    ENTITY_ID = ORG_NAME = AUTH_CLASS_REF = SUBJECT_ID = "reflector"

    def __init__(self, outgoing, internal_attributes, config, base_url, name):
        """
        :type outgoing:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response

        :type internal_attributes: dict[str, dict[str, list[str] | str]]
        :type config: dict[str, Any]
        :type base_url: str
        :type name: str

        :param outgoing: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Internal attribute map
        :param config: The module config
        :param base_url: base url of the service
        :param name: name of the plugin
        """
        super().__init__(outgoing, internal_attributes, base_url, name)

    def start_auth(self, context, internal_req):
        """
        See super class method satosa.backends.base.BackendModule#start_auth

        :type context: satosa.context.Context
        :type internal_req: satosa.internal.InternalData
        :rtype: satosa.response.Response
        """

        timestamp = datetime.utcnow().timestamp()
        auth_info = AuthenticationInformation(
            auth_class_ref=ReflectorBackend.AUTH_CLASS_REF,
            timestamp=timestamp,
            issuer=ReflectorBackend.ENTITY_ID,
        )

        internal_resp = InternalData(
            auth_info=auth_info,
            attributes={},
            subject_type=None,
            subject_id=ReflectorBackend.SUBJECT_ID,
        )

        return self.auth_callback_func(context, internal_resp)

    def register_endpoints(self):
        """
        See super class method satosa.backends.base.BackendModule#register_endpoints
        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]
        """
        url_map = []
        return url_map

    def get_metadata_desc(self):
        """
        See super class satosa.backends.backend_base.BackendModule#get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        entity_descriptions = []
        description = MetadataDescription(
            base64.urlsafe_b64encode(ReflectorBackend.ENTITY_ID.encode("utf-8")).decode(
                "utf-8"
            )
        )
        description.organization = ReflectorBackend.ORG_NAME

        entity_descriptions.append(description)
        return entity_descriptions
