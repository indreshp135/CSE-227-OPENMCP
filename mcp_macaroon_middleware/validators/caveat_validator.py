import logging
from datetime import datetime
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

        Args:
            caveat: The caveat to validate.

        Raises:
            CaveatValidationError: If the caveat is invalid.
        """
        logger.debug(f"Validating caveat: {caveat.raw}")
        if self._is_expired(caveat):
            logger.warning(f"Caveat expired: {caveat.raw}")
            raise CaveatValidationError(f"Caveat has expired: {caveat.raw}")
        logger.debug(f"Caveat '{caveat.raw}' is valid.")

    def _is_expired(self, caveat: Caveat) -> bool:
        """
        Checks if a caveat has expired.
        """
        if caveat.expiry.tzinfo is None:
            # If expiry is naive, assume UTC
            current_time = datetime.utcnow()
        else:
            current_time = datetime.now(caveat.expiry.tzinfo)
        
        is_expired = current_time > caveat.expiry
        logger.debug(f"Checking expiry for caveat '{caveat.raw}': current_time={current_time}, expiry={caveat.expiry}, expired={is_expired}")
        return is_expired
