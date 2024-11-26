import pytest

from copy import deepcopy

from ldap3 import AUTO_BIND_NO_TLS, MOCK_SYNC

from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services.ldap_attribute_store import LdapAttributeStore
from satosa.context import Context

import logging
logging.basicConfig(level=logging.DEBUG)

class TestLdapAttributeStore:
    ldap_attribute_store_config = {
        'default': {
            'auto_bind': 'AUTO_BIND_NO_TLS',
            'client_strategy': 'MOCK_SYNC',
            'ldap_url': 'ldap://satosa.example.com',
            'bind_dn': 'uid=readonly_user,ou=system,dc=example,dc=com',
            'bind_password': 'password',
            'search_base': 'ou=people,dc=example,dc=com',
            'query_return_attributes': [
                'givenName',
                'sn',
                'mail',
                'employeeNumber'
            ],
            'ldap_to_internal_map': {
                'givenName': 'givenname',
                'sn': 'sn',
                'mail': 'mail',
                'employeeNumber': 'employeenumber'
            },
            'clear_input_attributes': True,
            'ordered_identifier_candidates': [
                {'attribute_names': ['uid']}
            ],
            'ldap_identifier_attribute': 'uid'
        }
    }

    ldap_person_records = [
        ['employeeNumber=1000,ou=people,dc=example,dc=com', {
            'employeeNumber': '1000',
            'cn': 'Jane Baxter',
            'givenName': 'Jane',
            'sn': 'Baxter',
            'uid': 'jbaxter',
            'mail': 'jbaxter@example.com'
            }
         ],
        ['employeeNumber=1001,ou=people,dc=example,dc=com', {
            'employeeNumber': '1001',
            'cn': 'Booker Lawson',
            'givenName': 'Booker',
            'sn': 'Lawson',
            'uid': 'booker.lawson',
            'mail': 'blawson@example.com'
            }
         ],
    ]

    @pytest.fixture
    def ldap_attribute_store(self):
        store = LdapAttributeStore(self.ldap_attribute_store_config,
                                   name="test_ldap_attribute_store",
                                   base_url="https://satosa.example.com")

        # Mock up the 'next' microservice to be called.
        store.next = lambda ctx, data: data

        # We need to explicitly bind when using the MOCK_SYNC client strategy.
        connection = store.config['default']['connection']
        connection.bind()

        # Populate example records.
        for dn, attributes in self.ldap_person_records:
            attributes = deepcopy(attributes)
            connection.strategy.add_entry(dn, attributes)

        return store

    def test_attributes_general(self, ldap_attribute_store):
        ldap_to_internal_map = (self.ldap_attribute_store_config['default']
                                ['ldap_to_internal_map'])

        for dn, attributes in self.ldap_person_records:
            # Mock up the internal response the LDAP attribute store is
            # expecting to receive.
            response = InternalData(auth_info=AuthenticationInformation())

            # The LDAP attribute store configuration and the mock records
            # expect to use a LDAP search filter for the uid attribute.
            uid = attributes['uid']
            response.attributes = {'uid': uid}

            context = Context()
            context.state = dict()

            ldap_attribute_store.process(context, response)

            # Verify that the LDAP attribute store has retrieved the mock
            # records from the mock LDAP server and has added the appropriate
            # internal attributes.
            for ldap_attr, ldap_value in attributes.items():
                if ldap_attr in ldap_to_internal_map:
                    internal_attr = ldap_to_internal_map[ldap_attr]
                    response_attr = response.attributes[internal_attr]
                    assert(ldap_value in response_attr)

    @pytest.mark.parametrize(
        'config,connection_attributes',
        [
            (
                {
                    'auto_bind': 'AUTO_BIND_NO_TLS',
                    'client_strategy': 'MOCK_SYNC',
                    'ldap_url': 'ldap://satosa.example.com',
                    'bind_dn': 'uid=readonly_user,ou=system,dc=example,dc=com',
                    'bind_password': 'password',
                },
                {
                    'user': 'uid=readonly_user,ou=system,dc=example,dc=com',
                    'password': 'password',
                    'auto_bind': AUTO_BIND_NO_TLS,
                    'strategy_type': MOCK_SYNC,
                    'read_only': True,
                    'version': 3,
                    'pool_size': 10,
                    'pool_keepalive': 10,
                    'pool_lifetime': None,
                },
            ),
            (
                {
                    'auto_bind': 'AUTO_BIND_NO_TLS',
                    'client_strategy': 'MOCK_SYNC',
                    'ldap_url': 'ldap://satosa.example.com',
                    'bind_dn': 'uid=readonly_user,ou=system,dc=example,dc=com',
                    'bind_password': 'password',
                    'pool_size': 40,
                    'pool_keepalive': 41,
                    'pool_lifetime': 42,
                },
                {
                    'user': 'uid=readonly_user,ou=system,dc=example,dc=com',
                    'password': 'password',
                    'auto_bind': AUTO_BIND_NO_TLS,
                    'strategy_type': MOCK_SYNC,
                    'read_only': True,
                    'version': 3,
                    'pool_size': 40,
                    'pool_keepalive': 41,
                    'pool_lifetime': 42,
                },
            ),
        ]
    )
    def test_connection_config(self, config, connection_attributes):
        ldapAttributeStore = LdapAttributeStore({'default': config},
                                                name="test_ldap_attribute_store",
                                                base_url="https://satosa.example.com")
        connection = ldapAttributeStore.config['default']['connection']

        for k, v in connection_attributes.items():
            assert getattr(connection, k) == v
