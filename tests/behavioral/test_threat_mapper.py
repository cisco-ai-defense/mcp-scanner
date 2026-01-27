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
        
        valid_severities = ["HIGH", "MEDIUM", "LOW", "INFO"]
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
            "AGENT MASQUERADING",
            "DATA EXFILTRATION",
            "UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS",
            "UNAUTHORIZED OR UNSOLICITED SYSTEM ACCESS",
            "ARBITRARY RESOURCE READ/WRITE",
            "WEAK ACCESS CONTROLS",
            "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION",
            "BACKDOOR",
            "SAME-ORIGIN POLICY BYPASS",
            "CROSS-ORIGIN SECURITY BYPASS",
            "DEFENSE EVASION",
            "RESOURCE EXHAUSTION",
            "AUTOMATED FRAUD CONTENT GENERATION",
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
        
        # Should have at least 19 threat categories (comprehensive taxonomy)
        assert len(behavioral_threats) >= 19, f"Expected at least 19 threats, got {len(behavioral_threats)}"
    
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

    def test_agent_masquerading_threat_details(self):
        """Test specific details of AGENT MASQUERADING threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["AGENT MASQUERADING"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-3.1"
        assert threat["aitech_name"] == "Identity Manipulation"
        assert threat["aisubtech"] == "AISubtech-3.1.2"
        assert threat["aisubtech_name"] == "Trusted Agent Spoofing"
        assert "masquerading" in threat["description"].lower()
    
    def test_weak_access_controls_threat_details(self):
        """Test specific details of WEAK ACCESS CONTROLS threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["WEAK ACCESS CONTROLS"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-14.1"
        assert threat["aitech_name"] == "Privilege Compromise"
        assert threat["aisubtech"] == "AISubtech-14.1.2"
        assert threat["aisubtech_name"] == "Insufficient Access Controls"
        assert "access" in threat["description"].lower() or "authentication" in threat["description"].lower()
    
    def test_automated_fraud_content_generation_threat_details(self):
        """Test specific details of AUTOMATED FRAUD CONTENT GENERATION threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["AUTOMATED FRAUD CONTENT GENERATION"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-18.1"
        assert threat["aitech_name"] == "Financial and Fraud-Related Harm"
        assert threat["aisubtech"] == "AISubtech-18.1.1"
        assert threat["aisubtech_name"] == "Spam / Scam / Social Engineering Generation"
        assert "fraud" in threat["description"].lower() or "phishing" in threat["description"].lower()
    
    def test_same_origin_policy_bypass_threat_details(self):
        """Test specific details of SAME-ORIGIN POLICY BYPASS threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["SAME-ORIGIN POLICY BYPASS"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-4.3"
        assert threat["aitech_name"] == "Bypassing Security Mechanisms"
        assert threat["aisubtech"] == "AISubtech-4.3.4"
        assert threat["aisubtech_name"] == "Same-Origin Policy (SOP) Bypass"
        assert "same-origin" in threat["description"].lower() or "sop" in threat["description"].lower()
    
    def test_cross_origin_security_bypass_threat_details(self):
        """Test specific details of CROSS-ORIGIN SECURITY BYPASS threat."""
        from mcpscanner.threats.threats import ThreatMapping
        
        threat = ThreatMapping.BEHAVIORAL_THREATS["CROSS-ORIGIN SECURITY BYPASS"]
        
        assert threat["severity"] == "HIGH"
        assert threat["aitech"] == "AITech-4.3"
        assert threat["aitech_name"] == "Bypassing Security Mechanisms"
        assert threat["aisubtech"] == "AISubtech-4.3.6"
        assert threat["aisubtech_name"] == "Cross-Origin Exploitation"
        assert "cross-origin" in threat["description"].lower() or "trust boundaries" in threat["description"].lower()
