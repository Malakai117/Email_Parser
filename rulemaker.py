import yaml
import os
import re
from typing import List, Dict, Any

# config_file = "parsing_rules.yaml"

def load_config(config_file: str) -> Dict[str, Any]:
    """Load existing config or return empty structure."""
    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    return {}

def save_config(config: Dict[str, Any], config_file: str) -> None:
    """Save config using built-in safe YAML serialization."""
    with open(config_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config, f, indent=2, sort_keys=False, allow_unicode=True)
    print(f"{config_file} updated successfully!")

def validate_rule(provider: str, new_rule: Dict[str, str], config: Dict[str, Any]) -> None:
    """
    Validate a new rule before adding it.
    Raises ValueError with clear message if invalid.
    """
    label = new_rule.get("label")
    pattern = new_rule.get("pattern")
    type_ = new_rule.get("type", "str")

    if not label or not label.strip():
        raise ValueError("Rule 'label' cannot be empty.")

    if not pattern or not isinstance(pattern, str):
        raise ValueError("Rule 'pattern' must be a non-empty string.")

    if type_ not in {"str", "float", "int"}:
        raise ValueError(f"Invalid type '{type_}'. Must be 'str', 'float', or 'int'.")

    # Check for duplicate label within the same provider
    existing_labels = {
        rule["label"] for rule in config.get(provider, {}).get("rules", [])
    }
    if label in existing_labels:
        raise ValueError(f"Duplicate label '{label}' in provider '{provider}'. Labels must be unique.")

    # Most important: Test if the regex compiles
    try:
        re.compile(pattern)  # This will raise re.error if invalid
    except re.error as e:
        raise ValueError(f"Invalid regex pattern '{pattern}': {e}")

def add_rule(provider: str, label: str, pattern: str, type_: str = "str", config_file: str = "test.yaml") -> None:
    """
    Append a new rule to an existing provider.
    Uses raw strings for pattern — YAML handles escaping safely.
    """
    config = load_config(config_file)

    if provider not in config:
        raise ValueError(f"Provider '{provider}' not found. Use add_provider() first.")

    new_rule = {
        "label": label,
        "pattern": pattern,  # Keep as raw string, e.g. r"..."
        "type": type_
    }

    validate_rule(provider, new_rule, config)

    config[provider]["rules"].append(new_rule)
    save_config(config, config_file)
    print(f"Added rule '{label}' to provider '{provider}'")

def add_provider(provider: str, email: str, description: str, rules: List[Dict[str, str]], config_file: str) -> None:
    """
    Add a completely new provider with its description and list of rules.
    """
    config = load_config(config_file)

    temp_config = {provider: {"description": description, "rules": []}}
    for rule in rules:
        validate_rule(provider, rule, temp_config)

    if provider in config:
        print(f"Warning: Provider '{provider}' already exists. Updating it.")
        if not rules:
            rules = config[provider].get("rules", [])

    config[provider] = {
        "description": description,
        "email": email,
        "rules": rules  # Each rule: {"label": ..., "pattern": ..., "type": ...}
    }

    save_config(config, config_file)
    print(f"Added/Updated provider '{provider}' with {len(rules)} rules")

def create_initial_config(config_file) -> None:
    """Recreate the original PenTex config (useful for reset or first-time setup)."""
    initial_config = {
        "pentex": {
            "description": "PenTex Energy billing emails",
            "email": "sedc@pentex.com",
            "rules": [
                {"label": "Account",        "pattern": r"account\s*(\d+)",                  "type": "str"},
                {"label": "Balance",        "pattern": r"is\s*([\d,]+\.\d{2})",             "type": "float"},
                {"label": "Daily_Usage_kWh","pattern": r"(?:was|used)\s*([\d,]+)\s*kWh",      "type": "float"},
                {"label": "Payment_Amount", "pattern": r"\$\s*([\d,]+\.\d{2})",            "type": "float"},
            ]
        }
    }

    save_config(initial_config, config_file)
    print("Initial parsing_rules.yaml created!")

def remove_provider(provider: str, config_file: str = "test.yaml") -> None:
    """
    Completely remove a provider and all its rules.
    """
    config = load_config(config_file)

    if provider not in config:
        raise ValueError(f"Provider '{provider}' not found in the config.")

    del config[provider]
    save_config(config, config_file)
    print(f"Provider '{provider}' and all its rules have been removed successfully.")

def remove_rule(provider: str, label: str, config_file: str = "test.yaml") -> None:
    """
    Remove a single rule (by label) from a provider.
    """
    config = load_config(config_file)

    if provider not in config:
        raise ValueError(f"Provider '{provider}' not found in the config.")

    rules = config[provider].get("rules", [])
    original_count = len(rules)

    # Filter out the rule with the matching label
    config[provider]["rules"] = [rule for rule in rules if rule["label"] != label]

    if len(config[provider]["rules"]) == original_count:
        raise ValueError(f"No rule with label '{label}' found in provider '{provider}'.")

    save_config(config, config_file)
    print(f"Rule '{label}' removed from provider '{provider}' successfully.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manage parsing_rules.yaml — add providers and rules with full regex validation")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Command: init
    init_parser = subparsers.add_parser("init", help="Create or reset to initial config with paltex provider")
    init_parser.set_defaults(func=lambda args: create_initial_config())

    # Command: add-provider
    add_prov_parser = subparsers.add_parser("add-provider",help="Add or update a provider with one or more rules")
    add_prov_parser.add_argument("--provider", required=True, help="Provider key (e.g. paltex, newutility)")
    add_prov_parser.add_argument("--email", required=True, help="Sender's Email address")
    add_prov_parser.add_argument("--description", required=True, help="Human description of the provider")
    add_prov_parser.add_argument(
        "--rule",
        action="append",
        default=[],
        required=False,
        help="Rule in format label:pattern[:type]. Type is optional (str/float/int, default=str). "
             "Can be repeated. Example for CLI: --rule Account:r'account\\s*(\\d+)' --rule Balance:r'is\\s*([\\d,]+\\.\\d{2})':float"
    )

    def parse_rule_string(rule_str: str):
        if ':' not in rule_str:
            parser.error(f"Rule missing colon separator after label: '{rule_str}'")

        label_part, rest = rule_str.split(":", 1)
        label = label_part.strip()
        if not label:
            parser.error(f"Empty label in rule: '{rule_str}'")

        rest = rest.strip()

        possible_types = {"str": "str", "float": "float", "int": "int"}  # can add aliases if needed

        type_ = "str"
        pattern_part = rest
        for t in possible_types:
            type_suffix = ":" + t
            if rest.endswith(type_suffix):
                type_ = t
                pattern_part = rest[:-len(type_suffix)].strip()
                break

        if not pattern_part:
            parser.error(f"Empty pattern in rule: '{rule_str}'")

        pattern = pattern_part

        # Strip common raw string prefixes
        for prefix in ("r\"", 'r"', "r'", 'r\''):
            if pattern.startswith(prefix):
                pattern = pattern[len(prefix):]
                break

        # Strip matching suffixes
        for suffix in ('"', "'"):
            if pattern.endswith(suffix):
                pattern = pattern[:-1]
                break

        if not pattern:
            parser.error(f"Empty pattern after stripping quotes in rule: '{rule_str}'")

        return {"label": label, "pattern": pattern, "type": type_}

    def parse_add_provider(args):
        rules = []
        for rule_str in args.rule:
            try:
                rules.append(parse_rule_string(rule_str))
            except Exception as e:
                parser.error(f"Invalid rule '{rule_str}'", str(e))

        add_provider(args.provider, args.description, rules)

    add_prov_parser.set_defaults(func=parse_add_provider)


    # Command: add-rule
    add_rule_parser = subparsers.add_parser("add-rule",help="Add a single rule to an existing provider")
    add_rule_parser.add_argument("--provider", required=True, help="Existing provider key")
    add_rule_parser.add_argument("--label", required=True, help="Field label (e.g. Account, Balance)")
    add_rule_parser.add_argument("--pattern",required=True,help="Regex pattern as raw string, e.g. r\"account\\s*(\\d+)\" or \"account\\\\s*(\\\\d+)\"")
    add_rule_parser.add_argument("--type",default="str",choices=["str", "float", "int"],help="Value type: str (default), float, or int")
    add_rule_parser.set_defaults(func=lambda args: add_rule(args.provider, args.label, args.pattern, args.type))


    # Command: remove-provider
    remove_prov_parser = subparsers.add_parser("remove-provider",help="Completely remove a provider and all its rules")
    remove_prov_parser.add_argument("--provider", required=True, help="Provider key to remove")
    remove_prov_parser.set_defaults(func=lambda args: remove_provider(args.provider))

    # Command: remove-rule
    remove_rule_parser = subparsers.add_parser("remove-rule",help="Remove a single rule from a provider")
    remove_rule_parser.add_argument("--provider", required=True, help="Provider key")
    remove_rule_parser.add_argument("--label", required=True, help="Label of the rule to remove")
    remove_rule_parser.set_defaults(func=lambda args: remove_rule(args.provider, args.label))


    # Parse and execute
    args = parser.parse_args()
    args.func(args)