#!/usr/bin/env python3
"""
Rule Engine - Evaluates events against YAML-based detection rules

Supports:
- Hot-reload of rules without restart
- Multiple rule categories (usb, wifi, ble, network, airdrop)
- Complex condition evaluation (AND, OR, NOT)
- Multiple evaluator types (hash, pattern, behavioral)
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from .rule_loader import RuleLoader
from .evaluators.hash_evaluator import HashEvaluator
from .evaluators.pattern_evaluator import PatternEvaluator
from .evaluators.device_evaluator import DeviceEvaluator
from .evaluators.network_evaluator import NetworkEvaluator
from .evaluators.behavioral_evaluator import BehavioralEvaluator

logger = logging.getLogger(__name__)


class Rule:
    """Represents a single detection rule"""

    def __init__(self, rule_data: Dict[str, Any]):
        self.rule_id = rule_data.get('rule_id')
        self.name = rule_data.get('name')
        self.version = rule_data.get('version')
        self.enabled = rule_data.get('enabled', True)
        self.severity = rule_data.get('severity', 'medium')
        self.threat_type = rule_data.get('threat_type')
        self.category = rule_data.get('category')
        self.conditions = rule_data.get('conditions', {})
        self.actions = rule_data.get('actions', [])
        self.metadata = rule_data.get('metadata', {})
        self.tuning = rule_data.get('tuning', {})

    def __repr__(self):
        return f"Rule({self.rule_id}: {self.name})"


class RuleEngine:
    """
    Rule evaluation engine

    Loads YAML rules from directory and evaluates events against them.
    Supports hot-reload via reload_rules() method.
    """

    def __init__(self, rules_dir: str):
        """
        Initialize rule engine

        Args:
            rules_dir: Directory containing YAML rule files
        """
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, Rule] = {}
        self.rule_loader = RuleLoader()

        # Initialize evaluators
        self.evaluators = {
            'file_hash_match': HashEvaluator(),
            'device_vendor': DeviceEvaluator(),
            'device_product': DeviceEvaluator(),
            'file_pattern': PatternEvaluator(),
            'ssid_match': PatternEvaluator(),
            'network_pattern': NetworkEvaluator(),
            'behavioral': BehavioralEvaluator(),
            'signal_strength': NetworkEvaluator(),
            'mac_address': PatternEvaluator(),
            'service_name': PatternEvaluator(),
        }

        # Load rules on initialization
        self.load_rules()

    def load_rules(self):
        """Load all YAML rules from directory"""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory does not exist: {self.rules_dir}")
            return

        rule_count = 0

        # Walk through rules directory
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yaml') or file.endswith('.yml'):
                    rule_path = Path(root) / file

                    try:
                        rule_data = self.rule_loader.load_rule(str(rule_path))

                        if rule_data and rule_data.get('enabled', True):
                            rule = Rule(rule_data)
                            self.rules[rule.rule_id] = rule
                            rule_count += 1
                            logger.debug(f"Loaded rule: {rule.rule_id} from {file}")

                    except Exception as e:
                        logger.error(f"Failed to load rule from {file}: {e}")

        logger.info(f"Loaded {rule_count} detection rules from {self.rules_dir}")

    def reload_rules(self):
        """Hot-reload rules without restart"""
        logger.info("Reloading detection rules...")
        self.rules.clear()
        self.load_rules()
        logger.info("Rules reloaded successfully")

    def evaluate(self, event_data: Dict[str, Any], rule_set: str = 'all') -> List[Rule]:
        """
        Evaluate event against active rules

        Args:
            event_data: Event data dictionary from detector
            rule_set: Category filter ('all', 'usb', 'wifi', 'ble', 'network', 'airdrop')

        Returns:
            List of matched Rule objects
        """
        matches = []

        # Filter rules by category
        active_rules = self._get_active_rules(rule_set)

        # Evaluate each rule
        for rule_id, rule in active_rules.items():
            if self._evaluate_rule(event_data, rule):
                matches.append(rule)
                logger.debug(f"Rule matched: {rule.rule_id} - {rule.name}")

        return matches

    def _get_active_rules(self, category: str = 'all') -> Dict[str, Rule]:
        """
        Get rules filtered by category

        Args:
            category: Rule category filter

        Returns:
            Dictionary of filtered rules
        """
        if category == 'all':
            return self.rules

        return {
            rule_id: rule
            for rule_id, rule in self.rules.items()
            if rule.category == category
        }

    def _evaluate_rule(self, data: Dict[str, Any], rule: Rule) -> bool:
        """
        Evaluate single rule against data

        Args:
            data: Event data
            rule: Rule object

        Returns:
            True if rule matches, False otherwise
        """
        if not rule.enabled:
            return False

        conditions = rule.conditions
        operator = conditions.get('operator', 'AND')
        clauses = conditions.get('clauses', [])

        if not clauses:
            return False

        results = []

        # Evaluate each clause
        for clause in clauses:
            clause_type = clause.get('type')
            evaluator = self.evaluators.get(clause_type)

            if evaluator:
                try:
                    result = evaluator.evaluate(data, clause)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error evaluating clause {clause_type}: {e}")
                    results.append(False)
            else:
                logger.warning(f"No evaluator found for clause type: {clause_type}")
                results.append(False)

        # Apply boolean logic
        if operator == 'AND':
            return all(results)
        elif operator == 'OR':
            return any(results)
        elif operator == 'NOT':
            return not any(results)
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get rule by ID"""
        return self.rules.get(rule_id)

    def get_rules_by_category(self, category: str) -> List[Rule]:
        """Get all rules for a category"""
        return [
            rule for rule in self.rules.values()
            if rule.category == category
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get rule engine statistics"""
        categories = {}
        for rule in self.rules.values():
            category = rule.category
            if category not in categories:
                categories[category] = 0
            categories[category] += 1

        return {
            'total_rules': len(self.rules),
            'categories': categories,
            'rules_dir': str(self.rules_dir)
        }
