"""
Holds a base class for backend modules used in the SATOSA proxy.
"""

from ..attribute_mapping import AttributeMapper
from ..util import join_paths

from urllib.parse import urlparse


class BackendModule(object):
    """
    Base class for a backend module.
    """

    def __init__(self, auth_callback_func, internal_attributes, base_url, name):
        """
        :type auth_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type base_url: str
        :type name: str

        :param auth_callback_func: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param base_url: base url of the service
        :param name: name of the plugin
        """
        self.auth_callback_func = auth_callback_func
        self.internal_attributes = internal_attributes
        self.converter = AttributeMapper(internal_attributes)
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.base_path = urlparse(self.base_url).path.lstrip("/")
        self.name = name
        self.endpoint_baseurl = join_paths(self.base_url, self.name)
        self.endpoint_basepath = urlparse(self.endpoint_baseurl).path.lstrip("/")

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
