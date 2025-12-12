#!/usr/bin/env python3
"""Network-based evaluator for WiFi/network conditions"""

from typing import Dict, Any


class NetworkEvaluator:
    """Evaluates network-based conditions"""

    def evaluate(self, data: Dict[str, Any], clause: Dict[str, Any]) -> bool:
        """
        Evaluate network-based conditions

        Clause format:
        {
            "type": "signal_strength",
            "field": "rssi",
            "operator": "greater_than",
            "value": -50
        }
        """
        field = clause.get('field')
        operator = clause.get('operator', 'equals')
        expected_value = clause.get('value')

        if not field or expected_value is None:
            return False

        # Get value from event data
        actual_value = data.get(field)

        if actual_value is None:
            return False

        # Try to convert to numeric
        try:
            actual_value = float(actual_value)
            expected_value = float(expected_value)
        except (ValueError, TypeError):
            # Fall back to string comparison
            actual_value = str(actual_value)
            expected_value = str(expected_value)

        # Evaluate operator
        if operator == 'equals':
            return actual_value == expected_value
        elif operator == 'greater_than':
            return actual_value > expected_value
        elif operator == 'less_than':
            return actual_value < expected_value
        elif operator == 'greater_equal':
            return actual_value >= expected_value
        elif operator == 'less_equal':
            return actual_value <= expected_value
        elif operator == 'not_equals':
            return actual_value != expected_value
        else:
            return False
