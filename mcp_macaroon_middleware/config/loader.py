import logging
import yaml
from typing import List, Dict, Any
from ..exceptions import ConfigurationError

logger = logging.getLogger(__name__)

def load_policies_from_yaml(config_path: str) -> List[str]:
    """
    Loads initial macaroon caveat definitions from a YAML configuration file.

    Args:
        config_path: The path to the YAML configuration file.

    Returns:
        A list of caveat strings.
    """
    logger.info(f"Attempting to load policies from YAML file: {config_path}")
    try:
        with open(config_path, 'r') as file:
            policies_data = yaml.safe_load(file)
        logger.debug(f"Successfully loaded YAML data from {config_path}.")
    except FileNotFoundError:
        logger.error(f"Policy file not found at: {config_path}")
        raise ConfigurationError(f"Policy file not found at: {config_path}")
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {config_path}: {e}")
        raise ConfigurationError(f"Error parsing YAML file: {e}")

    if not isinstance(policies_data, dict) or "policies" not in policies_data:
        logger.error(f"YAML file {config_path} must contain a 'policies' root element.")
        raise ConfigurationError("YAML file must contain a 'policies' root element.")

    loaded_policies = policies_data.get("policies", [])
    logger.info(f"Loaded {len(loaded_policies)} policies from {config_path}.")
    return loaded_policies
