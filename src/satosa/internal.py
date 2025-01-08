"""Internal data representation for SAML/OAuth/OpenID connect."""


import warnings as _warnings
from collections import UserDict


class _Datafy(UserDict):
    _DEPRECATED_TO_NEW_MEMBERS = {}

    def _get_new_key(self, old_key):
        new_key = self.__class__._DEPRECATED_TO_NEW_MEMBERS.get(old_key, old_key)
        is_key_deprecated = old_key != new_key
        if is_key_deprecated:
            msg = "'{old_key}' is deprecated; use '{new_key}' instead.".format(
                old_key=old_key, new_key=new_key
            )
            _warnings.warn(msg, DeprecationWarning)
        return new_key

    def __setitem__(self, key, value):
        new_key = self._get_new_key(key)
        return super().__setitem__(new_key, value)

    def __getitem__(self, key):
        new_key = self._get_new_key(key)
        value = super().__getitem__(new_key)
        return value

    def __setattr__(self, key, value):
        if key == "data":
            return super().__setattr__(key, value)

        self.__setitem__(key, value)

    def __getattr__(self, key):
        if key == "data":
            return super().data

        try:
            value = self.__getitem__(key)
        except KeyError as e:
            msg = "'{type}' object has no attribute '{attr}'".format(
                type=type(self), attr=key
            )
            raise AttributeError(msg) from e
        return value

    def to_dict(self):
        """
        Converts an object to a dict
        :rtype: dict[str, str]
        :return: A dict representation of the object
        """
        data = {
            key: value
            for key, value_obj in self.items()
            for value in [
                value_obj.to_dict() if hasattr(value_obj, "to_dict") else value_obj
            ]
        }
        data.update(
            {
                key: data.get(value)
                for key, value in self.__class__._DEPRECATED_TO_NEW_MEMBERS.items()
            }
        )
        return data

    @classmethod
    def from_dict(cls, data):
        """
        :type data: dict[str, str]
        :rtype: satosa.internal.AuthenticationInformation
        :param data: A dict representation of an object
        :return: An object
        """
        instance = cls(**data.copy())
        return instance


class AuthenticationInformation(_Datafy):
    """
    Class that holds information about the authentication
    """

    def __init__(
        self,
        auth_class_ref=None,
        timestamp=None,
        issuer=None,
        authority=None,
        *args,
        **kwargs,
    ):
        """
        Initiate the data carrier

        :type auth_class_ref: str
        :type timestamp: str
        :type issuer: str

        :param auth_class_ref: What method that was used for the authentication
        :param timestamp: Time when the authentication was done
        :param issuer: Where the authentication was done
        """
        super().__init__(self, *args, **kwargs)
        self.auth_class_ref = auth_class_ref
        self.timestamp = timestamp
        self.issuer = issuer
        self.authority = authority


class LogoutInformation(_Datafy):
    """
    Class that holds information about the logout
    """

    def __init__(
        self,
        timestamp=None,
        issuer=None,
        status=None,
        *args,
        **kwargs,
    ):
        """
        :param timestamp: time when the logout was done
        :param issuer: where the logout was done
        :param status: status of the logout
        """
        super().__init__(self, *args, **kwargs)
        self.timestamp = timestamp
        self.issuer = issuer
        self.status = status


class InternalData(_Datafy):
    """
    A base class for the data carriers between frontends/backends
    """

    def __init__(
        self,
        auth_info=None,
        requester=None,
        requester_name=None,
        subject_id=None,
        subject_type=None,
        attributes=None,
        *args,
        **kwargs,
    ):
        """
        :param auth_info:
        :param requester: identifier of the requester
        :param requester_name:
        :param subject_id:
        :param subject_type:
        :param attributes:

        :type auth_info: AuthenticationInformation
        :type requester: str
        :type requester_name:
        :type subject_id: str
        :type subject_type: str
        :type attributes: dict
        """
        super().__init__(self, *args, **kwargs)
        self.auth_info = (
            auth_info
            if isinstance(auth_info, AuthenticationInformation)
            else AuthenticationInformation(**(auth_info or {}))
        )
        self.requester = requester
        self.requester_name = (
            requester_name
            if requester_name is not None
            else [{"text": requester, "lang": "en"}]
        )
        self.subject_id = subject_id
        self.subject_type = subject_type
        self.attributes = attributes if attributes is not None else {}
