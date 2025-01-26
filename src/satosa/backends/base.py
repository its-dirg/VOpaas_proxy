"""
Holds a base class for backend modules used in the SATOSA proxy.
"""

from ..attribute_mapping import AttributeMapper


class BackendModule(object):
    """
    Base class for a backend module.
    """

    def __init__(self, auth_callback_func, internal_attributes, base_url, name, storage, logout_callback_func):
        """
        :type auth_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type base_url: str
        :type name: str
        :type storage: satosa.storage.Storage
        :type logout_callback_func: str
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response


        :param auth_callback_func: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param base_url: base url of the service
        :param name: name of the plugin
        :param storage: storage to hold the backend session information
        :param logout_callback_func: Callback should be called by the module after the logout
        in the backend is done. This may trigger log out flow for all the frontends associated
        with the backend session
        """
        self.auth_callback_func = auth_callback_func
        self.internal_attributes = internal_attributes
        self.converter = AttributeMapper(internal_attributes)
        self.base_url = base_url
        self.name = name
        self.storage = storage
        self.logout_callback_func = logout_callback_func

    def start_auth(self, context, internal_request):
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Response

        :param context: the request context
        :param internal_request: Information about the authorization request
        :return: response
        """
        raise NotImplementedError()

    def register_endpoints(self):
        """
        Register backend functions to endpoint urls.

        Example of registering an endpoint:
            reg_endp = [
                ("^Saml2IDP/acs/redirect", endpoint_function),
            ]


        :rtype List[Tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, function), ...]
        """
        raise NotImplementedError()

    def get_metadata_desc(self):
        """
        Returns a description of the backend module.
        This is used when creating SAML metadata for the frontend of the proxy
        :rtype: satosa.metadata_creation.description.MetadataDescription
        :return: A description of the backend
        """
        raise NotImplementedError()
