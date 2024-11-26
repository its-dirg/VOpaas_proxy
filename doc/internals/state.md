# State

The SATOSA proxy uses a secure cookie to save state between different steps in
the transaction flow. The state is encrypted using an AES-256 cipher with
CBC mode and a random IV.
Through a complete flow, the state will at some point contain/have contained
the information described below. Additional information may have been stored
in the state by other plugins.

## SATOSA proxy

* **SESSION_ID**: This is a session id given by the satosa proxy
* **SATOSA_REQUESTER**: Id of the requester who called the proxy
* **IDHASHER.hash_type**: Which id type the requester is asking for (persistent/transient/...)
* **ROUTER**: Which frontend module that should answer the requester

### Consent module

If the consent is enabled, the consent module will save the following:

* **CONSENT.internal_resp.to**: To who the response should go (requester id)
* **CONSENT.internal_resp.auth_info.timestamp**: When the authentication was done
* **CONSENT.internal_resp.auth_info.auth_class_ref**: Description of how the authentication was determined
* **CONSENT.internal_resp.issuer**: Id of the identity provider
* **CONSENT.internal_resp.hash_type**: Which id type the requester is asking for (persistent/transient/...)
* **CONSENT.internal_resp.usr_id**: The id of the authenticated user
* **CONSENT.internal_resp.attr**: Contains all attributes and values given by the authentication
* **CONSENT.internal_resp.usr_id_attr**: An empty list
* **CONSENT.filter**: A list of all possible attributes that can be sent to the requester
* **CONSENT.requester_name**: The name of the requester

### Account linking module

If the account linking is enabled, the account linking module will save the following:

* **ACCOUNT_LINKING.to**: To who the response should go (requester id)
* **ACCOUNT_LINKING.auth_info.timestamp**: When the authentication was done
* **ACCOUNT_LINKING.auth_class_ref**: Description of how the authentication was determined
* **ACCOUNT_LINKING.issuer**: Id of the identity provider
* **ACCOUNT_LINKING.usr_id**: The id of the authenticated user
* **ACCOUNT_LINKING.attr**: Contains all attributes and values given by the authentication
* **ACCOUNT_LINKING.usr_id_attr**: An empty list
