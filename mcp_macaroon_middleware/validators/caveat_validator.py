import logging
from ..models.caveat import Caveat
from ..exceptions import CaveatValidationError

logger = logging.getLogger(__name__)

class CaveatValidator:
    """
    Validates individual caveats based on the policy rules.
    """

    def validate(self, caveat: Caveat):
        """
        Validates a single caveat.
        """
        logger.debug(f"Validating caveat: {caveat.raw}")
        # Add custom validation logic here if needed
        logger.debug(f"Caveat '{caveat.raw}' is valid.")