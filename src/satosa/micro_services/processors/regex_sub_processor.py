from ..attribute_processor import AttributeProcessorError, AttributeProcessorWarning
from .base_processor import BaseProcessor
import re
import logging

CONFIG_KEY_MATCH_PATTERN = 'regex_sub_match_pattern'
CONFIG_KEY_REPLACE_PATTERN = 'regex_sub_replace_pattern'
logger = logging.getLogger(__name__)
class RegexSubProcessor(BaseProcessor):
    """
    Performs a regex sub against an attribute value.
    Example configuration:
    module: satosa.micro_services.attribute_processor.AttributeProcessor
    name: AttributeProcessor
    config:
      process:
      - attribute: role
        processors:
        - name: RegexSubProcessor
          module: satosa.micro_services.custom.processors.regex_sub_processor
          regex_sub_match_pattern: (?<=saml-provider\/)(.*)(?=,)
          regex_sub_replace_pattern: \1-Test

    """

    def process(self, internal_data, attribute, **kwargs):
        regex_sub_match_pattern = r'{}'.format(kwargs.get(CONFIG_KEY_MATCH_PATTERN, ''))
        if regex_sub_match_pattern  == '':
            raise AttributeProcessorError("The regex_sub_match_pattern needs to be set")

        regex_sub_replace_pattern = r'{}'.format(kwargs.get(CONFIG_KEY_REPLACE_PATTERN, ''))
        if regex_sub_replace_pattern  == '':
            raise AttributeProcessorError("The regex_sub_replace_pattern needs to be set")
        attributes = internal_data.attributes

        values = attributes.get(attribute, [])
        new_values = []
        if not values:
            raise AttributeProcessorWarning("Cannot apply regex_sub to {}, it has no values".format(attribute))
        for value in values:
            new_values.append(re.sub(r'{}'.format(regex_sub_match_pattern), r'{}'.format(regex_sub_replace_pattern), value))
            logger.debug('regex_sub new_values: {}'.format(new_values))
        attributes[attribute] = new_values
