import logging
from collections import defaultdict
from itertools import chain
from typing import Any, Mapping, Optional, Union

from mako.template import Template

logger = logging.getLogger(__name__)


def scope(s: str) -> str:
    """
    Mako filter: used to extract scope from attribute
    :param s: string to extract scope from (filtered string in mako template)
    :return: the scope
    """
    if "@" not in s:
        raise ValueError("Unscoped string")
    (local_part, _, domain_part) = s.partition("@")
    return domain_part


class AttributeMapper(object):
    """
    Converts between internal and external data format
    """

    def __init__(self, internal_attributes: dict[str, dict[str, dict[str, list[str]]]]):
        """
        :param internal_attributes: A map of how to convert the attributes
        (dict[internal_name, dict[attribute_profile, external_name]])
        """
        self.separator = "."  # separator for nested attribute values, e.g. address.street_address
        self.multivalue_separator = ";"  # separates multiple values, e.g. when using templates
        self.from_internal_attributes = internal_attributes["attributes"]
        self.template_attributes = internal_attributes.get("template_attributes", None)

        self.to_internal_attributes: dict[str, Any] = defaultdict(dict)
        for internal_attribute_name, mappings in self.from_internal_attributes.items():
            for profile, external_attribute_names in mappings.items():
                for external_attribute_name in external_attribute_names:
                    self.to_internal_attributes[profile][external_attribute_name] = internal_attribute_name

    def to_internal_filter(self, attribute_profile: str, external_attribute_names: list[str]) -> list[str]:
        """
        Converts attribute names from external "type" to internal

        :param attribute_profile: From which external type to convert (ex: oidc, saml, ...)
        :param external_attribute_names: A list of attribute names
        :param case_insensitive: Create a case insensitive filter
        :return: A list of attribute names in the internal format
        """
        try:
            profile_mapping = self.to_internal_attributes[attribute_profile]
        except KeyError:
            logline = "no attribute mapping found for the given attribute profile {}".format(attribute_profile)
            logger.warn(logline)
            # no attributes since the given profile is not configured
            return []

        internal_attribute_names: set[str] = set()  # use set to ensure only unique values
        for external_attribute_name in external_attribute_names:
            try:
                internal_attribute_name = profile_mapping[external_attribute_name]
                internal_attribute_names.add(internal_attribute_name)
            except KeyError:
                pass

        return list(internal_attribute_names)

    def to_internal(self, attribute_profile: str, external_dict: Mapping[str, list[str]]) -> dict[str, list[str]]:
        """
        Converts the external data from "type" to internal

        :param attribute_profile: From which external type to convert (ex: oidc, saml, ...)
        :param external_dict: Attributes in the external format
        :return: Attributes in the internal format
        """
        internal_dict = {}

        for internal_attribute_name, mapping in self.from_internal_attributes.items():
            if attribute_profile not in mapping:
                logline = "no attribute mapping found for internal attribute {internal} the attribute profile {attribute}".format(
                    internal=internal_attribute_name, attribute=attribute_profile
                )
                logger.debug(logline)
                # skip this internal attribute if we have no mapping in the specified profile
                continue

            external_attribute_name = mapping[attribute_profile]
            attribute_values = self._collate_attribute_values_by_priority_order(external_attribute_name, external_dict)
            if attribute_values:  # Only insert key if it has some values
                logline = "backend attribute {external} mapped to {internal} ({value})".format(
                    external=external_attribute_name, internal=internal_attribute_name, value=attribute_values
                )
                logger.debug(logline)
                internal_dict[internal_attribute_name] = attribute_values
            else:
                logline = "skipped backend attribute {}: no value found".format(external_attribute_name)
                logger.debug(logline)
        internal_dict = self._handle_template_attributes(attribute_profile, internal_dict)
        return internal_dict

    def _collate_attribute_values_by_priority_order(
        self, attribute_names: list[str], data: Mapping[str, list[str]]
    ) -> list[str]:
        result: list[str] = []
        for attr_name in attribute_names:
            attr_val = self._get_nested_attribute_value(attr_name, data)

            if isinstance(attr_val, list):
                result.extend(attr_val)
            elif attr_val:
                result.append(attr_val)

        return result

    def _render_attribute_template(self, template: str, data: Mapping[str, list[str]]) -> list[str]:
        t = Template(template, cache_enabled=True, imports=["from satosa.attribute_mapping import scope"])
        try:
            _rendered = t.render(**data)
            if not isinstance(_rendered, str):
                raise TypeError("Rendered data is not a string")
            return _rendered.split(self.multivalue_separator)
        except (NameError, TypeError):
            return []

    def _handle_template_attributes(
        self, attribute_profile: str, internal_dict: dict[str, list[str]]
    ) -> dict[str, list[str]]:
        if not self.template_attributes:
            return internal_dict

        for internal_attribute_name, mapping in self.template_attributes.items():
            if attribute_profile not in mapping:
                # skip this internal attribute if we have no mapping in the specified profile
                continue

            external_attribute_name = mapping[attribute_profile]
            templates = [t for t in external_attribute_name if "$" in t]  # these looks like templates...
            template_attribute_values = [
                self._render_attribute_template(template, internal_dict) for template in templates
            ]
            flattened_attribute_values: list[str] = list(chain.from_iterable(template_attribute_values))
            attribute_values = flattened_attribute_values or internal_dict.get(internal_attribute_name)
            if attribute_values:  # only insert key if it has some values
                internal_dict[internal_attribute_name] = attribute_values

        return internal_dict

    def _get_nested_attribute_value(self, nested_key: str, data: Mapping[str, Any]) -> Optional[Any]:
        keys = nested_key.split(self.separator)

        d = data
        for key in keys:
            d = d.get(key)  # type: ignore[assignment]
            if d is None:
                return None
        return d

    def _create_nested_attribute_value(self, nested_attribute_names: list[str], value: Any) -> dict[str, Any]:
        if len(nested_attribute_names) == 1:
            # we've reached the inner-most attribute name, set value here
            return {nested_attribute_names[0]: value}

        # keep digging further into the nested attribute names
        child_dict = self._create_nested_attribute_value(nested_attribute_names[1:], value)
        return {nested_attribute_names[0]: child_dict}

    def from_internal(
        self, attribute_profile: str, internal_dict: dict[str, list[str]]
    ) -> dict[str, Union[list[str], dict[str, list[str]]]]:
        """
        Converts the internal data to "type"

        :param attribute_profile: To which external type to convert (ex: oidc, saml, ...)
        :param internal_dict: attributes to map
        :return: attribute values and names in the specified "profile"
        """
        external_dict: dict[str, Union[list[str], dict[str, list[str]]]] = {}
        for internal_attribute_name in internal_dict:
            try:
                attribute_mapping = self.from_internal_attributes[internal_attribute_name]
            except KeyError:
                logline = "no attribute mapping found for the internal attribute {}".format(internal_attribute_name)
                logger.debug(logline)
                continue

            if attribute_profile not in attribute_mapping:
                # skip this internal attribute if we have no mapping in the specified profile
                logline = "no mapping found for '{internal}' in attribute profile '{attribute}'".format(
                    internal=internal_attribute_name, attribute=attribute_profile
                )
                logger.debug(logline)
                continue

            external_attribute_names = self.from_internal_attributes[internal_attribute_name][attribute_profile]
            # select the first attribute name
            external_attribute_name = external_attribute_names[0]
            logline = "frontend attribute {external} mapped from {internal} ({value})".format(
                external=external_attribute_name,
                internal=internal_attribute_name,
                value=internal_dict[internal_attribute_name],
            )
            logger.debug(logline)

            if self.separator in external_attribute_name:
                nested_attribute_names = external_attribute_name.split(self.separator)
                nested_dict = self._create_nested_attribute_value(
                    nested_attribute_names[1:], internal_dict[internal_attribute_name]
                )
                external_dict[nested_attribute_names[0]] = nested_dict
            else:
                external_dict[external_attribute_name] = internal_dict[internal_attribute_name]

        return external_dict
