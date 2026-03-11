# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Data-type classifier for exfiltration findings.

Classifies what kind of sensitive data is being exfiltrated based on
variable names, string literals, env var accesses, and parameter names
found in the code context.
"""

import re
from dataclasses import dataclass, field
from typing import List, Set

from ...utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class DataClassification:
    """Classification result for sensitive data types."""

    categories: Set[str] = field(default_factory=set)
    evidence: List[str] = field(default_factory=list)

    @property
    def has_sensitive_data(self) -> bool:
        return len(self.categories) > 0

    @property
    def summary(self) -> str:
        if not self.categories:
            return "no sensitive data detected"
        return ", ".join(sorted(self.categories))


# Pattern definitions: (category, compiled_regex, description)
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_\-]?key|auth[_\-]?token)"),
    re.compile(r"(?i)(access[_\-]?key|secret[_\-]?key|private[_\-]?key|bearer)"),
    re.compile(r"(?i)(ssh[_\-]?key|rsa[_\-]?key|client[_\-]?secret|credentials?)"),
    re.compile(r"(?i)(aws[_\-]?secret|azure[_\-]?key|gcp[_\-]?key)"),
    re.compile(r"(?i)(database[_\-]?password|db[_\-]?pass|connection[_\-]?string)"),
]

_PII_PATTERNS = [
    re.compile(r"(?i)(ssn|social[_\-]?security|national[_\-]?id)"),
    re.compile(r"(?i)(email|e[_\-]?mail|phone|telephone|mobile)"),
    re.compile(r"(?i)(first[_\-]?name|last[_\-]?name|full[_\-]?name|birth[_\-]?date|dob)"),
    re.compile(r"(?i)(address|zip[_\-]?code|postal|city|state|country)"),
    re.compile(r"(?i)(passport|driver[_\-]?license|license[_\-]?number)"),
]

_FINANCIAL_PATTERNS = [
    re.compile(r"(?i)(credit[_\-]?card|card[_\-]?number|cvv|cvc|expir)"),
    re.compile(r"(?i)(bank[_\-]?account|routing[_\-]?number|iban|swift|bic)"),
    re.compile(r"(?i)(payment|billing|invoice|transaction)"),
]

_IP_PATTERNS = [
    re.compile(r"(?i)(proprietary|trade[_\-]?secret|confidential|internal[_\-]?only)"),
    re.compile(r"(?i)(source[_\-]?code|algorithm|model[_\-]?weights|training[_\-]?data)"),
]

_SYSTEM_PATTERNS = [
    re.compile(r"(?i)(/etc/shadow|/etc/passwd|\.ssh/|authorized_keys)"),
    re.compile(r"(?i)(\.env|\.aws/credentials|\.kube/config|kubeconfig)"),
    re.compile(r"(?i)(process[_\-]?list|system[_\-]?info|kernel|syslog)"),
]

_CATEGORY_PATTERN_MAP = {
    "CREDENTIALS": _CREDENTIAL_PATTERNS,
    "PII": _PII_PATTERNS,
    "FINANCIAL": _FINANCIAL_PATTERNS,
    "INTELLECTUAL_PROPERTY": _IP_PATTERNS,
    "SYSTEM_DATA": _SYSTEM_PATTERNS,
}


class DataClassifier:
    """Classifies sensitive data types from code context signals."""

    def classify_from_context(
        self,
        string_literals: List[str],
        env_var_access: List[str],
        parameter_names: List[str],
        variable_names: List[str],
    ) -> DataClassification:
        """Classify data types from various code context signals.

        Args:
            string_literals: String literals from the code
            env_var_access: Environment variable access patterns
            parameter_names: Function parameter names
            variable_names: Variable names from assignments

        Returns:
            DataClassification with detected categories and evidence
        """
        result = DataClassification()

        # Combine all signals into a single searchable corpus
        all_signals = (
            string_literals + env_var_access + parameter_names + variable_names
        )

        for signal in all_signals:
            for category, patterns in _CATEGORY_PATTERN_MAP.items():
                for pattern in patterns:
                    if pattern.search(signal):
                        if category not in result.categories:
                            result.categories.add(category)
                            result.evidence.append(
                                f"{category}: matched '{signal[:80]}'"
                            )
                        break  # One match per category per signal is enough

        return result

    def classify_finding_evidence(
        self, evidence_strings: List[str]
    ) -> DataClassification:
        """Classify data types from finding evidence strings.

        This is useful for enriching existing findings with data classification.

        Args:
            evidence_strings: Evidence strings from a finding

        Returns:
            DataClassification with detected categories
        """
        return self.classify_from_context(
            string_literals=evidence_strings,
            env_var_access=[],
            parameter_names=[],
            variable_names=[],
        )
