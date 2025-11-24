"""
Helper functions for text extraction and manipulation within the MCP Macaroon Middleware.
"""

import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .text_extraction_helpers import extract_content_to_dicts, update_result_with_dicts
	
__all__ = ["extract_content_to_dicts", "update_result_with_dicts"]