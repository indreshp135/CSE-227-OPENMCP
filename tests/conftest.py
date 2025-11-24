import pytest
import yaml

@pytest.fixture
def policies_yaml_file(tmp_path):
    """
    Creates a temporary policies.yaml file for testing.
    """
    config = {
        "config": {
            "secret_key": "test_secret_key",
            "elicit_expiry": 3600,
        },
        "policies": [
            "bf:test_tool:tool_access:allow",
            "af:test_tool:field_access:allow:some_field",
        ],
    }
    file_path = tmp_path / "policies.yaml"
    with open(file_path, "w") as f:
        yaml.dump(config, f)
    return file_path
