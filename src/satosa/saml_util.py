import requests

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP

from .response import SeeOther, Response


def make_saml_response(binding, http_args):
    """
    Creates a SAML response.
    :param binding: SAML response binding
    :param http_args: http arguments
    :return: response.Response
    """
    if binding == BINDING_HTTP_REDIRECT:
        headers = dict(http_args["headers"])
        return SeeOther(str(headers["Location"]))

    return Response(http_args["data"], headers=http_args["headers"])


def propagate_logout(binding, http_args):
    """
    :param binding: SAML response binding
    :param http_args: HTTP arguments

    :type binding: str
    :type http_args: dict
    """
    try:
        if binding == BINDING_HTTP_REDIRECT:
            headers = dict(http_args["headers"])
            requests.get(url=headers["Location"])
        elif binding == BINDING_SOAP:
            requests.post(
                url=http_args["url"],
                headers={"Content-type": "text/xml"},
                data=http_args['data']
            )
        else:
            requests.post(
                url=http_args['url'],
                headers=headers,
                data=http_args['data']
            )
    except requests.exceptions.RequestException as err:
        print("Error: {}".format(err))
