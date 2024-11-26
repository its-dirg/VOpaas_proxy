"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='8.4.0',
    description='Protocol proxy (SAML/OIDC).',
    author='DIRG',
    author_email='satosa-dev@lists.sunet.se',
    license='Apache 2.0',
    url='https://github.com/SUNET/SATOSA',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    install_requires=[
        "pyop >= v3.4.0",
        "pysaml2 >= 6.5.1",
        "pycryptodomex",
        "requests",
        "PyYAML",
        "gunicorn",
        "Werkzeug",
        "click",
        "chevron",
        "cookies-samesite-compat",
        "importlib-metadata >= 1.7.0; python_version <= '3.8'",
    ],
    extras_require={
        "ldap": ["ldap3"],
        "pyop_mongo": ["pyop[mongo]"],
        "pyop_redis": ["pyop[redis]"],
        "idpy_oidc_backend": ["idpyoidc >= 2.1.0"],
        "entraid_oidc_backend": ["msal==1.28.0"],
    },
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    entry_points={
        "console_scripts": ["satosa-saml-metadata=satosa.scripts.satosa_saml_metadata:construct_saml_metadata"]
    }
)
