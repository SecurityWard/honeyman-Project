#!/usr/bin/env python3
"""Hash-based evaluator for file signature matching"""

from typing import Dict, Any


class HashEvaluator:
    """Evaluates file hash conditions"""

    def evaluate(self, data: Dict[str, Any], clause: Dict[str, Any]) -> bool:
        """
        Evaluate hash-based conditions

        Clause format:
        {
            "type": "file_hash_match",
            "field": "sha256",  # or "md5"
            "operator": "in",
            "values": ["hash1", "hash2", ...]
        }
        """
        field = clause.get('field', 'sha256')
        operator = clause.get('operator', 'in')
        expected_values = clause.get('values', [])

        # Get hash from event data
        actual_value = data.get(field) or data.get('hashes', {}).get(field)

        if not actual_value:
            return False

        # Normalize hash (lowercase)
        actual_value = str(actual_value).lower()
        expected_values = [str(v).lower() for v in expected_values]

        # Evaluate operator
        if operator == 'in':
            return actual_value in expected_values
        elif operator == 'equals':
            return actual_value == expected_values[0] if expected_values else False
        elif operator == 'not_in':
            return actual_value not in expected_values
        else:
            return False
