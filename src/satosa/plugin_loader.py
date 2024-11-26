"""
Some help functions to load satosa backend and frontend modules
"""
import json
import logging
import sys
from contextlib import contextmanager
from pydoc import locate

from satosa.yaml import load as yaml_load
from satosa.yaml import YAMLError

from .backends.base import BackendModule
from .exception import SATOSAConfigurationError
from .frontends.base import FrontendModule
from .micro_services.base import (MicroService, RequestMicroService, ResponseMicroService)

logger = logging.getLogger(__name__)
names = []

@contextmanager
def prepend_to_import_path(import_paths):
    import_paths = import_paths or []
    for p in reversed(import_paths):  # insert the specified plugin paths in the same order
        sys.path.insert(0, p)
    yield
    del sys.path[0:len(import_paths)]  # restore sys.path


def load_backends(config, callback, internal_attributes):
    """
    Load all backend modules specified in the config

    :type config: satosa.satosa_config.SATOSAConfig
    :type callback:
    (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype: Sequence[satosa.backends.base.BackendModule]

    :param config: The configuration of the satosa proxy
    :param callback: Function that will be called by the backend after the authentication is done.
    :return: A list of backend modules
    """
    backend_modules = _load_plugins(
        config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
        config["BACKEND_MODULES"],
        backend_filter, config["BASE"],
        internal_attributes, callback)
  
    for backend in backend_modules:
        if backend.name in names:
            raise SATOSAConfigurationError("The name " + backend.name + " is taken!")

        else:
            names.append(backend.name)

    logger.info("Setup backends: {}".format([backend.name for backend in backend_modules]))
    return backend_modules


def load_frontends(config, callback, internal_attributes):
    """
    Load all frontend modules specified in the config

    :type config: satosa.satosa_config.SATOSAConfig
    :type callback:
    (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype: Sequence[satosa.frontends.base.FrontendModule]

    :param config: The configuration of the satosa proxy
    :param callback: Function that will be called by the frontend after the authentication request
    has been processed.
    :return: A list of frontend modules
    """
    frontend_modules = _load_plugins(config.get("CUSTOM_PLUGIN_MODULE_PATHS"), config["FRONTEND_MODULES"],
                                     frontend_filter, config["BASE"], internal_attributes, callback)
    
    for frontend in frontend_modules:
        if frontend.name in names:
            raise SATOSAConfigurationError("The name " + frontend.name + " is taken!")
        else:
            names.append(frontend.name)
    
    logger.info("Setup frontends: {}".format([frontend.name for frontend in frontend_modules]))
    return frontend_modules


def backend_filter(cls):
    """
    Verify that the type proper subclass of BackendModule.

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    return issubclass(cls, BackendModule) and cls != BackendModule


def frontend_filter(cls):
    """
    Verify that the type proper subclass of FrontendModule.

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    return issubclass(cls, FrontendModule) and cls != FrontendModule


def _micro_service_filter(cls):
    """
    Will only give a find on classes that is a subclass of MicroService, with the exception that
    the class is not allowed to be a direct ResponseMicroService or RequestMicroService.

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    is_microservice_module = issubclass(cls, MicroService)
    is_correct_subclass = cls != MicroService and cls != ResponseMicroService and cls != RequestMicroService
    return is_microservice_module and is_correct_subclass


def _request_micro_service_filter(cls):
    """
    Will only give a find on classes that is a subclass of RequestMicroService.
    Use this filter to only find frontend plugins

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    return issubclass(cls, RequestMicroService) and cls != RequestMicroService


def _response_micro_service_filter(cls):
    """
    Will only give a find on classes that is a subclass of ResponseMicroService.
    Use this filter to only find frontend plugins

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    return issubclass(cls, ResponseMicroService) and cls != ResponseMicroService


def _load_plugin_config(config):
    try:
        return yaml_load(config)
    except YAMLError as exc:
        if hasattr(exc, 'problem_mark'):
            mark = exc.problem_mark
            logger.error("Error position: ({line}:{column})".format(line=mark.line + 1, column=mark.column + 1))
            raise SATOSAConfigurationError("The configuration is corrupt.") from exc


def _load_plugins(plugin_paths, plugins, plugin_filter, base_url, internal_attributes, callback):
    """
    Loads endpoint plugins

    :type plugin_paths: list[str]
    :type plugins: list[str]
    :type plugin_filter: (type | str) -> bool
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype list[satosa.plugin_base.endpoint.InterfaceModulePlugin]

    :param plugin_paths: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :param plugin_filter: Filter what to load from the module file
    :param args: Arguments to the plugin
    :return: A list with all the loaded plugins
    """
    loaded_plugin_modules = []
    with prepend_to_import_path(plugin_paths):
        for plugin_config in plugins:
            try:
                module_class = _load_endpoint_module(plugin_config, plugin_filter)
            except SATOSAConfigurationError as e:
                raise SATOSAConfigurationError("Configuration error in {}".format(json.dumps(plugin_config))) from e

            if module_class:
                module_config = _replace_variables_in_plugin_module_config(plugin_config["config"], base_url,
                                                                           plugin_config["name"])
                instance = module_class(callback, internal_attributes, module_config, base_url,
                                        plugin_config["name"])
                loaded_plugin_modules.append(instance)
    return loaded_plugin_modules


def _load_endpoint_module(plugin_config, plugin_filter):
    _mandatory_params = ("name", "module", "config")
    if not all(k in plugin_config for k in _mandatory_params):
        raise SATOSAConfigurationError(
            "Missing mandatory plugin configuration parameter: {}".format(_mandatory_params))

    return _load_plugin_module(plugin_config, plugin_filter)


def _load_plugin_module(plugin_config, plugin_filter):
    module_class = locate(plugin_config["module"])
    if not module_class:
        raise ValueError("Can't find module '%s'" % plugin_config["module"])
    if not plugin_filter(module_class):
        return None

    return module_class


def _load_microservice(plugin_config, plugin_filter):
    _mandatory_params = ("name", "module")
    if not all(k in plugin_config for k in _mandatory_params):
        raise SATOSAConfigurationError(
            "Missing mandatory plugin configuration parameter: {}".format(_mandatory_params))

    return _load_plugin_module(plugin_config, plugin_filter)


def _load_microservices(plugin_paths, plugins, plugin_filter, internal_attributes, base_url):
    loaded_plugin_modules = []
    with prepend_to_import_path(plugin_paths):
        for plugin_config in plugins:
            try:
                module_class = _load_microservice(plugin_config, plugin_filter)
            except SATOSAConfigurationError as e:
                raise SATOSAConfigurationError("Configuration error in {}".format(json.dumps(plugin_config))) from e

            if module_class:
                instance = module_class(internal_attributes=internal_attributes, config=plugin_config.get("config"),
                                        name=plugin_config["name"], base_url=base_url)
                loaded_plugin_modules.append(instance)

    return loaded_plugin_modules


def _replace_variables_in_plugin_module_config(module_config, base_url, name):
    config = json.dumps(module_config)
    replace = [
        ("<base_url>", base_url),
        ("<name>", name)
    ]
    for _replace in replace:
        config = config.replace(_replace[0], _replace[1])
    return json.loads(config)


def load_request_microservices(plugin_path, plugins, internal_attributes, base_url):
    """
    Loads request micro services (handling incoming requests).

    :type plugin_path: list[str]
    :type plugins: list[str]
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :type base_url: str
    :rtype satosa.micro_service.service_base.RequestMicroService

    :param plugin_path: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :param: base_url: base url of the SATOSA server
    :return: Request micro service
    """
    request_services = _load_microservices(plugin_path, plugins, _request_micro_service_filter, internal_attributes,
                                           base_url)
    logger.info("Loaded request micro services: {}".format([type(k).__name__ for k in request_services]))
    return request_services


def load_response_microservices(plugin_path, plugins, internal_attributes, base_url):
    """
    Loads response micro services (handling outgoing responses).

    :type plugin_path: list[str]
    :type plugins: list[str]
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :type base_url: str
    :rtype satosa.micro_service.service_base.ResponseMicroService

    :param plugin_path: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :param: base_url: base url of the SATOSA server
    :return: Response micro service
    """
    response_services = _load_microservices(plugin_path, plugins, _response_micro_service_filter, internal_attributes,
                                            base_url)
    logger.info("Loaded response micro services:{}".format([type(k).__name__ for k in response_services]))
    return response_services
