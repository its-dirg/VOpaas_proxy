# saml-to-saml

## one-to-many
![](images/one-to-many_proxy_uscase.png "one-to-many proxy overview image")

1. The service provider sends a request to the proxy instance. The service provider only knows about the proxy and none of the actual identity providers.
1. The proxy redirects the user to the discovery service
1. The entity ID of the identity provider selected by the user is returned to the proxy
1. The proxy sent authentication request and when completed the the user get redirected back to the proxy
1. The response returned from the Identity provider is returned to the Service provider

## many-to-one
![](images/many-to-one.png "many-to-one proxy overview image")

1. Service provider sends request to proxy
1. Proxy communicates with the identity provider which normally can't talk to the service provider.
A reason for this could be that it can't handle multiple entity ID's or that they are not really
compatible.
1. Response returned by the identity provider containing the user information.
1. proxy returns the response to the service provider

# Installation
After following the [installation instructions](README.md#installation), the proxy must
be configured with a SAML2 frontend and an SAML2 backend.


# Configuration

1. Copy the necessary base configurations from the `<satosa_path>/example` directory:
   ```bash
   mkdir -p saml2-saml2/plugins
   cp example/{proxy_conf.yaml.example,internal_attributes.yaml.example} saml2-saml2/
   cp example/plugins/frontends/saml2_frontend.yaml.example saml2-saml2/plugins/
   cp example/plugins/backends/saml2_backend.yaml.example saml2-saml2/plugins/
   ```

1. Configure the proxy:
  1. Rename `proxy_conf.yaml.example` to `proxy_conf.yaml`:
     ```bash
     mv proxy_conf.yaml.example proxy_conf.yaml
     ```

  1. Edit the necessary proxy configuration parameters, see the [SATOSA proxy
     configuration](README.md#proxy_conf) section of the proxy configuration instructions
     for more information.
     To specify the necessary plugins make sure to include the following
     configuration parameter values:
     ```yaml
     BACKEND_MODULES:
       - saml2-saml2/plugins/saml2_backend.yaml
     FRONTEND_MODULES:
       - saml2-saml2/plugins/saml2_frontend.yaml
     ```

1. Configure the attribute mapping:
  1. Rename `internal_attributes.yaml.example` to `internal_attributes.yaml`:
     ```bash
     mv internal_attributes.yaml.example internal_attributes.yaml
     ```

  1. Map the necessary attributes, see the [Attribute mapping configuration](README.md#attribute-mapping-configuration-internal_attributesyaml)
     section of the proxy configuration instructions for more
     information.

1. Configure the plugins
  1. Rename `plugins/saml2_frontend.yaml.example` to `plugins/saml2_frontend.yaml`
     and `plugins/saml2_backend.yaml.example` to `plugins/saml2_backend.yaml`
     ```bash
     mv plugins/saml2_frontend.yaml.example plugins/saml2_frontend.yaml
     mv plugins/saml2_backend.yaml.example plugins/saml2_backend.yaml
     ```

  1. Specify the necessary configuration parameters, see the [Plugins](README.md#plugins) section
     of the proxy configuration instructions for more information.

1. Generate the SAML metadata, see the [SAML metadata](README.md#saml_metadata) section of the
   proxy configuration instructions for more information.

# Run
1. Start the proxy application, see the [Running the proxy application](README.md#run) section of
   the proxy configuration instructions for more information.
