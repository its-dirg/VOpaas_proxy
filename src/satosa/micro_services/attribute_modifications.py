import re
import logging

from .base import ResponseMicroService
from ..context import Context
from ..exception import SATOSAError

logger = logging.getLogger(__name__)


class AddStaticAttributes(ResponseMicroService):
    """
    Add static attributes to the responses.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.static_attributes = config["static_attributes"]

    def process(self, context, data):
        data.attributes.update(self.static_attributes)
        return super().process(context, data)


class AddMetadataAttributes(ResponseMicroService):
    """
    Add metadata-derived attributes to the responses.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_mapping = config["attribute_mapping"]

    def process(self, context, data):
        data.attributes.update(self.get_attribute_values(context, data.auth_info.issuer, self.attribute_mapping))
        return super().process(context, data)

    def get_attribute_values(self, context, target_provider, attribute_mapping):
        attribute_values = {}
        mdstore = context.get_decoration(Context.KEY_METADATA_STORE)
        if not mdstore:
            return attribute_values  # empty: nothing we can do without an mdstore
        for am in attribute_mapping:
            value = None
            if am['type'] == "shibmd_scopes":
                scopes = mdstore.shibmd_scopes(target_provider, "idpsso_descriptor")

                # saml2.MDStore.shibmd_scopes returns compiled RE Pattern objects, but these are not serializable.
                # Replace them back with the original pattern text.
                # And wrap the resulting list in a dict, as mod_auth_openidc does not accept lists of JSON objects.
                value = {"scopes":
                         [
                             {"regexp": scope['regexp'], "text": scope['text'].pattern if scope['regexp'] else scope['text']}
                             for scope in scopes
                         ]}
            elif am['type'] == "contact_person_data":
                # Convert tuple to a list to make it serializable.
                # And wrap it in a dict, as mod_auth_openidc does not accept lists of JSON objects.
                value = {"contacts": list(mdstore.contact_person_data(target_provider))}
            elif am['type'] == "assurance_certifications":
                # Convert tuple to a list to make it serializable.
                value = list(mdstore.assurance_certifications(target_provider))
            elif am['type'] == "registration_info":
                value = mdstore.registration_info(target_provider)
            elif am['type'] == "registration_authority":
                registration_info = mdstore.registration_info(target_provider)
                if registration_info and 'registration_authority' in registration_info:
                    value = registration_info['registration_authority']
            elif am['type'] == "entity_categories":
                value = mdstore.entity_categories(target_provider)
            elif am['type'] == "supported_entity_categories":
                value = mdstore.supported_entity_categories(target_provider)
            elif am['type'] == "entity_attributes":
                value = mdstore.entity_attributes(target_provider)
            else:
                raise SATOSAError("Unknown SAML metadata attribute type")

            if value:
                attribute_values[am['name']] = value
        return attribute_values


class FilterAttributeValues(ResponseMicroService):
    """
    Filter attribute values, only preserving those matching the given regex.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_filters = config["attribute_filters"]

    def process(self, context, data):
        # apply default filters
        provider_filters = self.attribute_filters.get("", {})
        target_provider = data.auth_info.issuer
        self._apply_requester_filters(data.attributes, provider_filters, data.requester, context, target_provider)

        # apply target provider specific filters
        provider_filters = self.attribute_filters.get(target_provider, {})
        self._apply_requester_filters(data.attributes, provider_filters, data.requester, context, target_provider)
        return super().process(context, data)

    def _apply_requester_filters(self, attributes, provider_filters, requester, context, target_provider):
        # apply default requester filters
        default_requester_filters = provider_filters.get("", {})
        self._apply_filters(attributes, default_requester_filters, context, target_provider)

        # apply requester specific filters
        requester_filters = provider_filters.get(requester, {})
        self._apply_filters(attributes, requester_filters, context, target_provider)

    def _apply_filters(self, attributes, attribute_filters, context, target_provider):
        for attribute_name, attribute_filters in attribute_filters.items():
            if type(attribute_filters) == str:
                # convert simple notation to filter list
                attribute_filters = {'regexp': attribute_filters}

            for filter_type, filter_value in attribute_filters.items():

                if filter_type == "regexp":
                    filter_func = re.compile(filter_value).search
                elif filter_type == "shibmdscope_match_scope":
                    mdstore = context.get_decoration(Context.KEY_METADATA_STORE)
                    md_scopes = list(mdstore.shibmd_scopes(target_provider,"idpsso_descriptor")) if mdstore else []
                    filter_func = lambda v: self._shibmdscope_match_scope(v, md_scopes)
                elif filter_type == "shibmdscope_match_value":
                    mdstore = context.get_decoration(Context.KEY_METADATA_STORE)
                    md_scopes = list(mdstore.shibmd_scopes(target_provider,"idpsso_descriptor")) if mdstore else []
                    filter_func = lambda v: self._shibmdscope_match_value(v, md_scopes)
                else:
                    raise SATOSAError("Unknown filter type")

                if attribute_name == "":  # default filter for all attributes
                    for attribute, values in attributes.items():
                        attributes[attribute] = list(filter(filter_func, attributes[attribute]))
                elif attribute_name in attributes:
                    attributes[attribute_name] = list(filter(filter_func, attributes[attribute_name]))

    def _shibmdscope_match_value(self, value, md_scopes):
        for md_scope in md_scopes:
            if not md_scope['regexp'] and md_scope['text'] == value:
                return True
            elif md_scope['regexp'] and re.fullmatch(md_scope['text'], value):
                return True
        return False

    def _shibmdscope_match_scope(self, value, md_scopes):
        split_value = value.split('@')
        if len(split_value) != 2:
            logger.info(f"Discarding invalid scoped value {value}")
            return False
        value_scope = split_value[1]
        return self._shibmdscope_match_value(value_scope, md_scopes)
