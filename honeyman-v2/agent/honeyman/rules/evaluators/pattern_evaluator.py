#!/usr/bin/env python3
"""Pattern-based evaluator for regex and string matching"""

import re
from typing import Dict, Any


class PatternEvaluator:
    """Evaluates pattern/regex conditions"""

    def evaluate(self, data: Dict[str, Any], clause: Dict[str, Any]) -> bool:
        """
        Evaluate pattern-based conditions

        Clause format:
        {
            "type": "file_pattern",
            "field": "filename",
            "operator": "regex",  # or "contains", "equals", "startswith", "endswith"
            "pattern": "^malware.*\\.exe$"
        }
        """
        field = clause.get('field')
        operator = clause.get('operator', 'regex')
        pattern = clause.get('pattern', '')

        if not field or not pattern:
            return False

        # Get value from event data
        actual_value = data.get(field)

        if actual_value is None:
            return False

        actual_value = str(actual_value)

        # Evaluate based on operator
        if operator == 'regex':
            try:
                return bool(re.search(pattern, actual_value, re.IGNORECASE))
            except re.error:
                return False

        elif operator == 'contains':
            return pattern.lower() in actual_value.lower()

        elif operator == 'equals':
            return actual_value.lower() == pattern.lower()

        elif operator == 'startswith':
            return actual_value.lower().startswith(pattern.lower())

        elif operator == 'endswith':
            return actual_value.lower().endswith(pattern.lower())

        else:
            return False
