import pytest

from satosa.context import Context
from satosa.routing import ModuleRouter, SATOSANoBoundEndpointError
from tests.util import TestBackend, TestFrontend, TestRequestMicroservice, TestResponseMicroservice

FRONTEND_NAMES = ["Saml2IDP", "VOPaaSSaml2IDP"]
BACKEND_NAMES = ["Saml2SP", "VOPaaSSaml2SP"]


class TestModuleRouter:
    @pytest.fixture(autouse=True)
    def create_router(self):
        backends = []
        for provider in BACKEND_NAMES:
            backends.append(TestBackend(None, {"attributes": {}}, None, None, provider, None))

        frontends = []
        for receiver in FRONTEND_NAMES:
            frontends.append(TestFrontend(None, {"attributes": {}}, None, None, receiver, None))

        request_micro_service_name = "RequestService"
        response_micro_service_name = "ResponseService"
        microservices = [TestRequestMicroservice(request_micro_service_name, base_url="https://satosa.example.com"),
                         TestResponseMicroservice(response_micro_service_name, base_url="https://satosa.example.com")]

        self.router = ModuleRouter(frontends, backends, microservices)

    @pytest.mark.parametrize('url_path, expected_frontend, expected_backend', [
        ("%s/%s/request" % (provider, receiver), receiver, provider)
        for receiver in FRONTEND_NAMES
        for provider in BACKEND_NAMES
        ])
    def test_endpoint_routing_to_frontend(self, url_path, expected_frontend, expected_backend):
        context = Context()
        context.path = url_path
        self.router.endpoint_routing(context)
        assert context.target_frontend == expected_frontend
        assert context.target_backend == expected_backend

    @pytest.mark.parametrize('url_path, expected_backend', [
        ("%s/response" % (provider,), provider) for provider in BACKEND_NAMES
        ])
    def test_endpoint_routing_to_backend(self, url_path, expected_backend):
        context = Context()
        context.path = url_path
        self.router.endpoint_routing(context)
        assert context.target_backend == expected_backend
        assert context.target_frontend is None

    @pytest.mark.parametrize('url_path, expected_micro_service', [
        ("request_microservice/callback", "RequestService"),
        ("response_microservice/callback", "ResponseService")
    ])
    def test_endpoint_routing_to_microservice(self, url_path, expected_micro_service):
        context = Context()
        context.path = url_path
        microservice_callable = self.router.endpoint_routing(context)
        assert context.target_micro_service == expected_micro_service
        assert microservice_callable == self.router.micro_services[expected_micro_service]["instance"].callback
        assert context.target_backend is None
        assert context.target_frontend is None

    @pytest.mark.parametrize('url_path, expected_frontend, expected_backend', [
        ("%s/%s/request" % (provider, receiver), receiver, provider)
        for receiver in FRONTEND_NAMES
        for provider in BACKEND_NAMES
        ])
    def test_module_routing(self, url_path, expected_frontend, expected_backend, context):
        context.path = url_path

        self.router.endpoint_routing(context)
        assert context.target_backend == expected_backend
        assert context.target_frontend == expected_frontend

        backend = self.router.backend_routing(context)
        assert backend == self.router.backends[expected_backend]["instance"]
        frontend = self.router.frontend_routing(context)
        assert frontend == self.router.frontends[expected_frontend]["instance"]

    def test_endpoint_routing_with_unknown_endpoint(self, context):
        context.path = "unknown"
        with pytest.raises(SATOSANoBoundEndpointError):
            self.router.endpoint_routing(context)

    @pytest.mark.parametrize(("frontends", "backends", "micro_services"), [
        (None, None, {}),
        ({}, {}, {}),
    ])
    def test_bad_init(self, frontends, backends, micro_services):
        with pytest.raises(ValueError):
            ModuleRouter(frontends, backends, micro_services)
