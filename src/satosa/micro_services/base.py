"""
Micro service for SATOSA
"""
import logging
from urllib.parse import urlparse

from ..util import join_paths

logger = logging.getLogger(__name__)


class MicroService(object):
    """
    Abstract class for micro services
    """

    def __init__(self, name, base_url, **kwargs):
        self.name = name
        self.base_url = base_url
        self.base_path = urlparse(base_url).path.lstrip("/")
        self.endpoint_baseurl = join_paths(self.base_url, self.name)
        self.endpoint_basepath = urlparse(self.endpoint_baseurl).path.lstrip("/")
        self.next = None

    def process(self, context, data):
        """
        This is where the micro service should modify the request / response.
        Subclasses must call this method (or in another way make sure the `next`
        callable is called).

        :type context: satosa.context.Context
        :type data: satosa.internal.InternalData
        :rtype: satosa.internal.InternalData

        :param context: The current context
        :param data: Data to be modified
        :return: Modified data
        """
        return self.next(context, data)

    def register_endpoints(self):
        """
        URL mapping of additional endpoints this micro service needs to register for callbacks.

        Example of a mapping from the url path '/callback' to the callback() method of a micro service:
            reg_endp = [
                ("^/callback1$", self.callback),
            ]


        :rtype List[Tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, Callable[[satosa.context.Context], satosa.response.Response]), ...]
        """
        return []


class ResponseMicroService(MicroService):
    """
    Base class for response micro services
    """
    pass


class RequestMicroService(MicroService):
    """
    Base class for request micro services
    """
    pass
