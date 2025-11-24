import logging
import yaml
from typing import List, Dict, Any
from ..exceptions import ConfigurationError

logger = logging.getLogger(__name__)

def load_config_from_yaml(config_path: str) -> Dict[str, Any]:
    """
    Loads macaroon caveat definitions and configuration from a YAML file.

    Args:
        config_path: The path to the YAML configuration file.

    Returns:
        A dictionary with 'policies' and 'config' keys.
    """
    logger.info(f"Attempting to load configuration from YAML file: {config_path}")
    try:
        with open(config_path, 'r') as file:
            data = yaml.safe_load(file)
        logger.debug(f"Successfully loaded YAML data from {config_path}.")
    except FileNotFoundError:
        logger.error(f"Policy file not found at: {config_path}")
        raise ConfigurationError(f"Policy file not found at: {config_path}")
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {config_path}: {e}")
        raise ConfigurationError(f"Error parsing YAML file: {e}")

    if not isinstance(data, dict):
        logger.error(f"YAML file {config_path} must be a dictionary.")
        raise ConfigurationError("YAML file must be a dictionary.")

    config = {
        "policies": data.get("policies", []),
        "config": data.get("config", {})
    }
    
    logger.info(f"Loaded {len(config['policies'])} policies and {len(config['config'])} config items from {config_path}.")
    return config
