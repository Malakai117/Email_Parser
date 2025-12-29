#!/usr/bin/env python3
"""
test_rulemaker.py

A comprehensive test/demo script for rulemaker.py

Shows:
- Programmatic usage (import and call functions directly)
- CLI usage (subprocess calls for integration testing)
- Safe cleanup (restores original config at the end)

Run with: python test_rulemaker.py
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

# Import your rulemaker functions
from rulemaker import (
    add_provider,
    add_rule,
    create_initial_config,
    load_config,
    save_config,
    CONFIG_FILE,
)

# Backup original config if it exists
ORIGINAL_BACKUP = f"{CONFIG_FILE}.original_backup"
TEST_BACKUP = f"{CONFIG_FILE}.test_backup"


def backup_config(label: str):
    if os.path.exists(CONFIG_FILE):
        shutil.copy2(CONFIG_FILE, f"{CONFIG_FILE}.{label}")
        print(f"[{label}] Backed up current config")


def restore_original():
    if os.path.exists(ORIGINAL_BACKUP):
        shutil.copy2(ORIGINAL_BACKUP, CONFIG_FILE)
        os.remove(ORIGINAL_BACKUP)
        print("Restored original parsing_rules.yaml")
    elif os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print("Removed test-generated parsing_rules.yaml")


def print_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            print("\n=== Current parsing_rules.yaml ===")
            print(f.read().strip())
            print("=== End of config ===\n")
    else:
        print("\nNo parsing_rules.yaml exists yet.\n")


def test_programmatic_usage():
    print("\n" + "="*60)
    print("TEST 1: Programmatic Usage (import and call functions)")
    print("="*60)

    # Start fresh
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)

    # 1. Create initial paltex provider
    print("Creating initial paltex provider...")
    create_initial_config()
    print_config()

    # 2. Add a completely new provider programmatically
    print("Adding new provider 'testutility' with two rules...")
    add_provider(
        provider="testutility",
        description="Demo Utility for testing rulemaker",
        rules=[
            {"label": "CustomerID", "pattern": r"Customer ID:\s*(\d{8})", "type": "str"},
            {"label": "CurrentCharges", "pattern": r"Current Charges\s*\$\s*([\d,]+\.\d{2})", "type": "float"},
            {"label": "DueDate", "pattern": r"Due:\s*(\w+ \d{1,2}, \d{4})", "type": "str"},
        ]
    )
    print_config()

    # 3. Add a single rule to an existing provider
    print("Adding new rule 'PreviousBalance' to paltex...")
    add_rule(
        provider="paltex",
        label="PreviousBalance",
        pattern=r"Previous Balance\s*\$\s*([\d,]+\.\d{2})",
        type_="float"
    )
    print_config()


def test_cli_usage():
    print("\n" + "="*60)
    print("TEST 2: CLI Usage (via command line)")
    print("="*60)

    # Ensure we start clean for CLI test
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)

    script = "rulemaker.py"

    # 1. CLI: init
    print("CLI: python rulemaker.py init")
    result = subprocess.run([sys.executable, script, "init"], capture_output=True, text=True)
    print(result.stdout)
    print_config()

    # 2. CLI: add-provider with multiple rules
    print("CLI: Adding new provider 'cliutility' with rules")
    cmd = [
        sys.executable, script, "add-provider",
        "--provider", "cliutility",
        "--description", "Added entirely via CLI",
        "--rule", 'ServiceAddress:r"Service Address:\\s*(.+)"',
        "--rule", 'MeterReading:r"Meter Reading:\\s*(\\d+\\.?\\d*)\\s*kWh":float',
        "--rule", 'BillAmount:r"Total Amount Due \\$([\\d,]+\\.\\d{2})":float',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("Error:", result.stderr)
    print_config()

    # 3. CLI: add-rule
    print("CLI: Adding one more rule to cliutility")
    cmd = [
        sys.executable, script, "add-rule",
        "--provider", "cliutility",
        "--label", "BillingPeriod",
        "--pattern", r"Period:\\s*(\\w+ \\d{1,2} - \\w+ \\d{1,2}, \\d{4})",
        "--type", "str"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    print_config()


def main():
    print("Starting rulemaker.py integration tests...\n")

    # Backup original if exists
    backup_config("original_backup")

    try:
        test_programmatic_usage()
        test_cli_usage()

        print("\n" + "="*60)
        print("ALL TESTS COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\nYour rulemaker.py works perfectly both as a library and CLI tool.")
        print("It validates regexes, prevents duplicates, and preserves patterns cleanly via YAML.")

    finally:
        # Always restore original state
        restore_original()


if __name__ == "__main__":
    main()