# Running SATOSA Using Apache HTTP Server and mod\_wsgi

This document describes how to deploy and run the SATOSA proxy using
Apache HTTP Server and mod\_wsgi. To be concrete this document details
deploying SATOSA on the latest CentOS 7.x release.

## Dependencies

```
yum install epel-release
yum install httpd mod_ssl httpd-devel python34 python34-devel
yum install xmlsec1-openssl gcc curl
```

Install the latest production release of pip and use it to install the latest
production release of mod\_wsgi:

```
curl https://bootstrap.pypa.io/get-pip.py | python3
pip install mod_wsgi
```

Create a `satosa` user to run the WSGI daemon:

```
useradd --home-dir /etc/satosa --no-create-home --system --user-group satosa
```

## Installation

Use pip to install SATOSA:

```
pip install SATOSA
```

To instead install the latest from the master branch on the GitHub repository:

```
yum install git
pip install --upgrade git+https://github.com/IdentityPython/SATOSA.git#egg=SATOSA
```

To upgrade and use the latest release of pySAML2:

```
pip install --upgrade pysaml2
```

## Installation of SATOSA Microservices

```
curl -L -o satosa_microservices.tar.gz \
    https://github.com/IdentityPython/satosa_microservices/archive/master.tar.gz \
    && mkdir -p /opt/satosa_microservices \
    && tar -zxf satosa_microservices.tar.gz -C /opt/satosa_microservices --strip-components=1 \
    && rm -f satosa_microservices.tar.gz
```

If you need the LDAP Attribute Store microservice you must also install
ldap3 using pip:

```
pip install ldap3
```

## Apache Configuration

Use the `mod_wsgi-express module-config` command to determine the correct
module path and Python home to add to the Apache configuration. For
example:

```
$ mod_wsgi-express module-config
LoadModule wsgi_module "/usr/lib64/python3.4/site-packages/mod_wsgi/server/mod_wsgi-py34.cpython-34m.so"
WSGIPythonHome "/usr"
```

Edit the Apache config and in the global section (not within a virtual
host) add the `LoadModule` and `WSGIPythonHome` lines as output from the
above command.

Edit the Apache config and in your virtual host configuration add

```
WSGIDaemonProcess satosa processes=2 threads=15 \
  display-name=%{GROUP} home=/etc/satosa user=satosa group=satosa \
  restart-interval=86400 graceful-timeout=3600 \
  python-path=/opt/satosa_microservices/src/satosa/micro_services:/etc/satosa

WSGIApplicationGroup satosa
WSGIProcessGroup satosa

WSGIScriptAlias / /usr/lib/python3.4/site-packages/satosa/wsgi.py
WSGICallableObject app
WSGIImportScript /usr/lib/python3.4/site-packages/satosa/wsgi.py \
  process-group=satosa application-group=satosa

# ensure authorization headers are transmitted to the application
WSGIPassAuthorization On
```

## SATOSA Configuration

Create the directory `/etc/satosa` and in it the SATOSA `proxy_conf.yaml`
configuration file. For example

```
$ mkdir /etc/satosa
$ cat << EOF > /etc/satosa/proxy_conf.yaml

BASE: https://some.host.org

STATE_ENCRYPTION_KEY: fazmC8yELv38f9PF0kbS

INTERNAL_ATTRIBUTES: "/etc/satosa/internal_attributes.yaml"

COOKIE_STATE_NAME: "SATOSA_STATE"

BACKEND_MODULES:
  - "/etc/satosa/plugins/saml2_backend.yaml"

FRONTEND_MODULES:
  - "/etc/satosa/plugins/ping_frontend.yaml"
  - "/etc/satosa/plugins/saml2_frontend.yaml"

MICRO_SERVICES:
  - "/etc/satosa/plugins/primary_identifier.yaml"
  - "/etc/satosa/plugins/ldap_attribute_store.yaml"

CONSENT:
  enable: No

ACCOUNT_LINKING:
  enable: No

LOGGING:
  version: 1
  formatters:
    simple:
      format: "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
  handlers:
    console:
      class: logging.StreamHandler
      formatter: simple
      stream: ext://sys.stderr
  loggers:
    satosa:
      level: INFO
      handlers:
        - console
      propagate: no
  root:
    level: INFO
    handlers:
      - console
```

Complete the SATOSA configuration as detailed in your `proxy_conf.yaml`
file. See the [SATOSA configuration reference](./README.md) for details.

After SATOSA is configured restart the Apache server:


```
systemctl restart httpd
```

## Logging

SATOSA log output is sent to the Apache server logs as configured in the
Apache configuration.


## Overriding Errors

The body of the HTML sent by SATOSA when it encounters an error condition
is not user friendly. To configure Apache to catch errors returned by
SATOSA and override the HTML displayed add to the global Apache config

```
WSGIErrorOverride On
```

Then in the virtual host add before the WSGIScriptAlias for example

```
ErrorDocument 404 /error.html
ErrorDocument 500 /error.html

Alias /error.html /var/www/html/error.html
```









