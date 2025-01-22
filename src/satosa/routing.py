"""
Holds satosa routing logic
"""
import logging
import re

from satosa.exception import SATOSABadContextError
from satosa.exception import SATOSANoBoundEndpointError

import satosa.logging_util as lu


logger = logging.getLogger(__name__)

STATE_KEY = "ROUTER"


class ModuleRouter(object):
    class UnknownEndpoint(ValueError):
        pass

    """
    Routes url paths to their bound functions
    and handles the internal routing between frontends and backends.
    """

    def __init__(self, frontends, backends, micro_services, base_path=None):
        """
        :type frontends: dict[str, satosa.frontends.base.FrontendModule]
        :type backends: dict[str, satosa.backends.base.BackendModule]
        :type micro_services: Sequence[satosa.micro_services.base.MicroService]
        :type base_path: str

        :param frontends: All available frontends used by the proxy. Key as frontend name, value as
        module
        :param backends: All available backends used by the proxy. Key as backend name, value as
        module
        :param micro_services: All available micro services used by the proxy. Key as micro service name, value as
        module
        :param base_path: Base path for endpoint mapping
        """

        if not frontends or not backends:
            raise ValueError("Need at least one frontend and one backend")

        backend_names = [backend.name for backend in backends]
        self.frontends = {instance.name: {"instance": instance,
                                          "endpoints": instance.register_endpoints(backend_names)}
                          for instance in frontends}
        self.backends = {instance.name: {"instance": instance, "endpoints": instance.register_endpoints()}
                         for instance in backends}

        if micro_services:
            self.micro_services = {instance.name: {"instance": instance, "endpoints": instance.register_endpoints()}
                                   for instance in micro_services}
        else:
            self.micro_services = {}

        self.base_path = base_path if base_path else ""

        logger.debug("Loaded backends with endpoints: {}".format(backends))
        logger.debug("Loaded frontends with endpoints: {}".format(frontends))
        logger.debug("Loaded micro services with endpoints: {}".format(micro_services))

    def backend_routing(self, context):
        """
        Returns the targeted backend and an updated state

        :type context: satosa.context.Context
        :rtype satosa.backends.base.BackendModule

        :param context: The request context
        :return: backend
        """
        msg = "Routing to backend: {backend}".format(backend=context.target_backend)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        backend = self.backends[context.target_backend]["instance"]
        context.state[STATE_KEY] = context.target_frontend
        return backend

    def frontend_routing(self, context):
        """
        Returns the targeted frontend and original state

        :type context: satosa.context.Context
        :rtype satosa.frontends.base.FrontendModule

        :param context: The response context
        :return: frontend
        """

        target_frontend = context.state[STATE_KEY]
        msg = "Routing to frontend: {frontend}".format(frontend=target_frontend)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        context.target_frontend = target_frontend
        frontend = self.frontends[context.target_frontend]["instance"]
        return frontend

    def _find_registered_endpoint_for_module(self, module, context):
        for regex, spec in module["endpoints"]:
            match = re.search(regex, context.path)
            if match is not None:
                msg = "Found registered endpoint: module name:'{name}', endpoint: {endpoint}".format(
                    name=module["instance"].name, endpoint=context.path
                )
                logline = lu.LOG_FMT.format(
                    id=lu.get_session_id(context.state), message=msg
                )
                logger.debug(logline)
                return spec

        return None

    def _find_registered_backend_endpoint(self, context):
        return self._find_registered_endpoint_for_module(self.backends[context.target_backend], context)

    def _find_registered_endpoint(self, context, modules):
        for module in modules.values():
            matched = self._find_registered_endpoint_for_module(module, context)
            if matched:
                return module["instance"].name, matched

        raise ModuleRouter.UnknownEndpoint(context.path)

    def _find_backend(self, request_path):
        """
        Tries to guess the backend in use from the request.
        Returns the backend name or None if the backend was not specified.
        """
        request_path = request_path.lstrip("/")
        if self.base_path and request_path.startswith(self.base_path):
            request_path = request_path[len(self.base_path):].lstrip("/")
        backend_guess = request_path.split("/")[0]
        if backend_guess in self.backends:
            return backend_guess
        return None

    def endpoint_routing(self, context):
        """
        Finds and returns the endpoint function bound to the path

        :type context: satosa.context.Context
        :rtype: ((satosa.context.Context, Any) -> Any, Any)

        :param context: The request context
        :return: registered endpoint and bound parameters
        """
        if context.path is None:
            msg = "Context did not contain a path!"
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSABadContextError("Context did not contain any path")

        msg = "Routing path: {path}".format(path=context.path)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        backend = self._find_backend(context.path)
        if backend is not None:
            context.target_backend = backend
        else:
            msg = "No backend was specified in request or no such backend {}".format(backend)
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)

        try:
            name, frontend_endpoint = self._find_registered_endpoint(context, self.frontends)
        except ModuleRouter.UnknownEndpoint:
            for frontend in self.frontends.values():
                logger.debug(f"Unable to find {context.path} in {frontend['endpoints']}")
            pass
        else:
            context.target_frontend = name
            return frontend_endpoint

        try:
            name, micro_service_endpoint = self._find_registered_endpoint(context, self.micro_services)
        except ModuleRouter.UnknownEndpoint:
            pass
        else:
            context.target_micro_service = name
            return micro_service_endpoint

        if backend is not None:
            backend_endpoint = self._find_registered_backend_endpoint(context)
            if backend_endpoint:
                return backend_endpoint

        raise SATOSANoBoundEndpointError("'{}' not bound to any function".format(context.path))
