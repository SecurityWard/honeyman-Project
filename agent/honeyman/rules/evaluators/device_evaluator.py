#!/usr/bin/env python3
"""Device-based evaluator for USB/BLE device matching"""

from typing import Dict, Any


class DeviceEvaluator:
    """Evaluates device vendor/product conditions"""

    def evaluate(self, data: Dict[str, Any], clause: Dict[str, Any]) -> bool:
        """
        Evaluate device-based conditions

        Clause format:
        {
            "type": "device_vendor",
            "field": "vid",  # or "pid", "vendor", "product"
            "operator": "equals",  # or "in"
            "value": "0x1234"  # or values: [...]
        }
        """
        field = clause.get('field')
        operator = clause.get('operator', 'equals')

        if not field:
            return False

        # Get value from event data
        actual_value = data.get(field)

        if actual_value is None:
            return False

        # Normalize hex values
        actual_value = str(actual_value).lower()

        # Handle single value or list
        if 'value' in clause:
            expected_value = str(clause['value']).lower()
            return actual_value == expected_value

        elif 'values' in clause:
            expected_values = [str(v).lower() for v in clause['values']]
            return actual_value in expected_values

        return False
