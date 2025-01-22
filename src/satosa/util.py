"""
Python package file for util functions.
"""
import hashlib
import logging
import random
import string
import typing


logger = logging.getLogger(__name__)


def hash_data(salt, value, hash_alg=None):
    """
    Hashes a value together with a salt with the given hash algorithm.

    :type salt: str
    :type hash_alg: str
    :type value: str
    :param salt: hash salt
    :param hash_alg: the hash algorithm to use (default: SHA512)
    :param value: value to hash together with the salt
    :return: hashed value
    """
    hash_alg = hash_alg or 'sha512'
    hasher = hashlib.new(hash_alg)
    hasher.update(value.encode('utf-8'))
    hasher.update(salt.encode('utf-8'))
    value_hashed = hasher.hexdigest()
    return value_hashed


def check_set_dict_defaults(dic, spec):
    for path, value in spec.items():
        keys = path.split('.')
        try:
            _val = dict_get_nested(dic, keys)
        except KeyError:
            if type(value) is list:
                value_default = value[0]
            else:
                value_default = value
            dict_set_nested(dic, keys, value_default)
        else:
            if type(value) is list:
                is_value_valid = _val in value
            elif type(value) is dict:
                # do not validate dict
                is_value_valid = bool(_val)
            else:
                is_value_valid = _val == value
            if not is_value_valid:
                logline = (
                    "Incompatible configuration value '{value}' for '{path}'. "
                    "Value shoud be: {expected}"
                ).format(value=_val, path=path, expected=value)
                logger.warning(logline)
    return dic


def dict_set_nested(dic, keys, value):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    dic[keys[-1]] = value


def dict_get_nested(dic, keys):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    return dic[keys[-1]]


def get_dict_defaults(d, *keys):
    for key in keys:
        d = d.get(key, d.get("", d.get("default", {})))
    return d


def rndstr(size=16, alphabet=""):
    """
    Returns a string of random ascii characters or digits
    :type size: int
    :type alphabet: str
    :param size: The length of the string
    :param alphabet: A string with characters.
    :return: string
    """
    rng = random.SystemRandom()
    if not alphabet:
        alphabet = string.ascii_letters[0:52] + string.digits
    return type(alphabet)().join(rng.choice(alphabet) for _ in range(size))


def join_paths(*paths, sep: typing.Optional[str] = None) -> str:
    """
    Joins strings with a separator like they were path components. The
    separator is stripped off from all path components, except for the
    beginning of the first component. Empty (or falsy) components are skipped.
    Note that the components are not sanitized in any other way.

    Raises TypeError if any of the components are not strings (or empty).
    """
    sep = sep or "/"
    leading = ""
    if paths and paths[0] and paths[0][0] == sep:
        leading = sep

    try:
        return leading + sep.join(
            path.strip(sep) for path in filter(lambda p: p and p.strip(sep), paths)
        )
    except (AttributeError, TypeError) as err:
        raise TypeError("Arguments must be strings") from err
