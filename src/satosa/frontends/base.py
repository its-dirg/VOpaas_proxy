"""
Holds a base class for frontend modules used in the SATOSA proxy.
"""
from ..attribute_mapping import AttributeMapper


class FrontendModule(object):
    """
    Base class for a frontend module.
    """

    def __init__(self, auth_req_callback_func, internal_attributes, base_url, name, logout_req_callback_func=None):
        """
        :type auth_req_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[str, dict[str, str | list[str]]]
        :type name: str

        :param auth_req_callback_func: Callback should be called by the module after the
        authorization response has been processed.
        :param name: name of the plugin
        """
        self.auth_req_callback_func = auth_req_callback_func
        self.logout_req_callback_func = logout_req_callback_func
        self.internal_attributes = internal_attributes
        self.converter = AttributeMapper(internal_attributes)
        self.base_url = base_url
        self.name = name

    def handle_authn_response(self, context, internal_resp):
        """
        If an authorization has been successful in a backend, this function is called and is
        supposed to send an authorization response to the client.

        :type context: satosa.context.Context
        :type internal_resp: satosa.internal.InternalData
        :rtype satosa.response.Response

        :param context: The request context
        :param internal_resp: Attributes from the authorization
        :return response
        """
        raise NotImplementedError()

    def handle_backend_error(self, exception):
        """
        IF the backend gets an unexpected error, a suitable notice about the failure should be sent
        to the requester. This function is supposed to send a suitable error message to the
        requester.

        :type exception: satosa.exception.SATOSAError
        :rtype: satosa.response.Response

        :param exception: The raised exception
        :return: response
        """
        raise NotImplementedError()

    def register_endpoints(self, backend_names):
        """
        Register frontend functions to endpoint urls.

        Example of registering an endpoint:
            providers = ["Saml2IDP", "OIDCOP"]
            reg_endp = [
                ("^Saml2IDP/sso/redirect$", endpoint_function),
                ("^OIDCOP/sso/redirect$", endpoint_function),
            ]


        :type backend_names: list[str]
        :rtype List[Tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]

        :param backend_names: Names of all all configured backends.
            All regexes produced for the frontends authentication endpoint must contain each backend name, e.g.:

                urls = []
                for name in backend_names:
                    urls.append("{}/authentication".format(name))

                urls.append("global_endpoint")
                return urls

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, function), ...]
        """
        raise NotImplementedError()
