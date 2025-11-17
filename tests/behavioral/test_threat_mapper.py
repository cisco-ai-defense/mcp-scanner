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

"""Tests for ThreatMapper component."""

import pytest


class TestThreatMapper:
    """Test ThreatMapper functionality."""
    
    def test_threat_mappings_exist(self):
        """Test that threat mappings exist."""
        from mcpscanner.threats import threats
        assert threats is not None
        assert hasattr(threats, 'ThreatMapping')
    
    def test_behavioral_threats_available(self):
        """Test that behavioral threat mappings are available."""
        from mcpscanner.threats.threats import ThreatMapping
        
        # Test that behavioral threats are defined
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        assert behavioral_threats is not None
        assert "DATA EXFILTRATION" in behavioral_threats
        
        data_exfil = behavioral_threats["DATA EXFILTRATION"]
        assert "aitech" in data_exfil
        assert "severity" in data_exfil
        assert "scanner_category" in data_exfil
    
    def test_behavioral_threat_categories(self):
        """Test that behavioral threat categories exist with proper structure."""
        from mcpscanner.threats.threats import ThreatMapping
        
        # Test that BEHAVIORAL_THREATS exists and has entries
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        assert behavioral_threats is not None
        assert len(behavioral_threats) > 0, "Should have at least one behavioral threat"
        
        # Verify structure of each threat
        for threat_name, threat_data in behavioral_threats.items():
            assert "aitech" in threat_data, f"Missing aitech for {threat_name}"
            assert "aitech_name" in threat_data, f"Missing aitech_name for {threat_name}"
            assert "aisubtech" in threat_data, f"Missing aisubtech for {threat_name}"
            assert "aisubtech_name" in threat_data, f"Missing aisubtech_name for {threat_name}"
            assert "severity" in threat_data, f"Missing severity for {threat_name}"
            assert "scanner_category" in threat_data, f"Missing scanner_category for {threat_name}"
    
    def test_threat_severity_levels(self):
        """Test that threats have valid severity levels."""
        from mcpscanner.threats.threats import ThreatMapping
        
        valid_severities = ["HIGH", "MEDIUM", "LOW"]
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        for threat_name, threat_data in behavioral_threats.items():
            assert threat_data["severity"] in valid_severities, \
                f"Invalid severity for {threat_name}: {threat_data['severity']}"
    
    def test_aitech_taxonomy_format(self):
        """Test that AITech taxonomy follows correct format."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        for threat_name, threat_data in behavioral_threats.items():
            aitech = threat_data["aitech"]
            assert aitech.startswith("AITech-"), f"Invalid AITech format for {threat_name}"
            
            aisubtech = threat_data["aisubtech"]
            assert aisubtech.startswith("AISubtech-"), f"Invalid AISubtech format for {threat_name}"
    
    def test_threat_descriptions_exist(self):
        """Test that all threats have descriptions."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        for threat_name, threat_data in behavioral_threats.items():
            assert "description" in threat_data, f"Missing description for {threat_name}"
            assert len(threat_data["description"]) > 50, \
                f"Description too short for {threat_name}"
    
    def test_data_exfiltration_threat_details(self):
        """Test specific details of DATA EXFILTRATION threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["DATA EXFILTRATION"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-8.2"
        assert "exfiltration" in threat["description"].lower()
    
    def test_aitech_taxonomy_format(self):
        """Test that AITech taxonomy follows correct format."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        for threat_name, threat_data in behavioral_threats.items():
            # Check AITech format: AITech-X.Y
            aitech = threat_data["aitech"]
            assert aitech.startswith("AITech-"), f"Invalid AITech format for {threat_name}"
            assert len(aitech.split("-")) == 2, f"Invalid AITech format for {threat_name}"
            
            # Check AISubtech format: AISubtech-X.Y.Z
            aisubtech = threat_data["aisubtech"]
            assert aisubtech.startswith("AISubtech-"), f"Invalid AISubtech format for {threat_name}"
            assert len(aisubtech.split("-")) == 2, f"Invalid AISubtech format for {threat_name}"
    
    def test_specific_threat_categories(self):
        """Test specific threat categories are present."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        # Critical threats that should exist
        expected_critical_threats = [
            "DATA EXFILTRATION",
            "INJECTION ATTACKS",  # Plural to match BEHAVIORAL_THREATS
        ]
        
        for threat_name in expected_critical_threats:
            assert threat_name in behavioral_threats, f"Missing critical threat: {threat_name}"
            assert behavioral_threats[threat_name]["severity"] == "HIGH", \
                f"{threat_name} should be HIGH severity"
    
    def test_threat_descriptions_exist(self):
        """Test that all threats have descriptions."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        for threat_name, threat_data in behavioral_threats.items():
            assert "description" in threat_data, f"Missing description for {threat_name}"
            assert len(threat_data["description"]) > 50, \
                f"Description too short for {threat_name}"
    
    def test_scanner_categories_valid(self):
        """Test that scanner categories are valid."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        valid_categories = [
            "PROMPT INJECTION",
            "INJECTION ATTACKS",  # Plural
            "TEMPLATE INJECTION",
            "TOOL POISONING",
            "GOAL MANIPULATION",
            "DATA EXFILTRATION",
            "UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS",
            "UNAUTHORIZED OR UNSOLICITED SYSTEM ACCESS",
            "ARBITRARY RESOURCE READ/WRITE",
            "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION",
            "BACKDOOR",
            "DEFENSE EVASION",
            "RESOURCE EXHAUSTION",
            "GENERAL DESCRIPTION-CODE MISMATCH"
        ]
        
        for threat_name, threat_data in behavioral_threats.items():
            scanner_cat = threat_data["scanner_category"]
            assert scanner_cat in valid_categories, \
                f"Invalid scanner category for {threat_name}: {scanner_cat}"
    
    def test_behavioral_threats_count(self):
        """Test that there are multiple behavioral threats defined."""
        from mcpscanner.threats.threats import ThreatMapping
        
        behavioral_threats = ThreatMapping.BEHAVIORAL_THREATS
        
        # Should have at least 14 threat categories (comprehensive taxonomy)
        assert len(behavioral_threats) >= 14, f"Expected at least 14 threats, got {len(behavioral_threats)}"
    
    def test_data_exfiltration_threat_details(self):
        """Test specific details of DATA EXFILTRATION threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["DATA EXFILTRATION"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-8.2"
        assert "Data Exfiltration" in threat["aitech_name"]
        assert threat["aisubtech"] == "AISubtech-8.2.3"
        assert "Agent Tooling" in threat["aisubtech_name"]
        assert "extracting" in threat["description"].lower() or "exfiltration" in threat["description"].lower()
    
    def test_injection_attack_threat_details(self):
        """Test specific details of INJECTION ATTACKS threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["INJECTION ATTACKS"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-9.1"
        assert len(threat["description"]) > 50, "Description should be detailed"
