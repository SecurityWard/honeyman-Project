#!/usr/bin/env python3
"""
Rule Loader - Loads and validates YAML rule files
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class RuleLoader:
    """Loads and validates YAML detection rules"""

    REQUIRED_FIELDS = ['rule_id', 'name', 'version', 'category', 'threat_type', 'severity']

    def load_rule(self, rule_path: str) -> Optional[Dict[str, Any]]:
        """
        Load a single rule from YAML file

        Args:
            rule_path: Path to YAML rule file

        Returns:
            Rule data dictionary or None if invalid
        """
        try:
            with open(rule_path, 'r') as f:
                rule_data = yaml.safe_load(f)

            if not rule_data:
                logger.warning(f"Empty rule file: {rule_path}")
                return None

            # Validate required fields
            if not self._validate_rule(rule_data):
                logger.error(f"Invalid rule structure in {rule_path}")
                return None

            return rule_data

        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {rule_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading rule from {rule_path}: {e}")
            return None

    def _validate_rule(self, rule_data: Dict[str, Any]) -> bool:
        """
        Validate rule structure

        Args:
            rule_data: Rule dictionary

        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in rule_data:
                logger.error(f"Missing required field: {field}")
                return False

        # Validate severity
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        if rule_data.get('severity') not in valid_severities:
            logger.error(f"Invalid severity: {rule_data.get('severity')}")
            return False

        # Validate conditions structure
        conditions = rule_data.get('conditions', {})
        if not conditions:
            logger.error("Rule has no conditions")
            return False

        if 'clauses' not in conditions:
            logger.error("Conditions missing 'clauses' field")
            return False

        return True

    def save_rule(self, rule_data: Dict[str, Any], output_path: str):
        """
        Save rule to YAML file

        Args:
            rule_data: Rule dictionary
            output_path: Path to save YAML file
        """
        try:
            with open(output_path, 'w') as f:
                yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Saved rule to {output_path}")

        except Exception as e:
            logger.error(f"Error saving rule to {output_path}: {e}")
            raise
