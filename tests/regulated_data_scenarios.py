"""Scenario fixtures for regulated-data (PII/PHI/PCI) prompt tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Expect = Literal["SAFE", "HIGH"]


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    category: str
    expect: Expect
    parameters: dict[str, Any] | None = None
    expect_threats: tuple[str, ...] = ()


FALSE_POSITIVE_SCENARIOS: list[Scenario] = [
    Scenario(
        name="bigcommerce_anonymize_customer",
        category="defensive_pii",
        description="Anonymize PII for a BigCommerce customer.",
        parameters={
            "customer_id": {"type": "string", "description": "Customer Id"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="hipaa_compliance_audit",
        category="defensive_phi",
        description=(
            "Scan connected systems for HIPAA compliance gaps and generate "
            "a remediation report. Does not return raw patient records."
        ),
        parameters={
            "scope": {"type": "string", "description": "Audit scope identifier"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="pci_dss_compliance_scan",
        category="defensive_pci",
        description=(
            "Run a PCI-DSS compliance assessment against configured endpoints "
            "and return pass/fail control findings without exporting cardholder data."
        ),
        parameters={
            "merchant_id": {"type": "string", "description": "Merchant account id"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="redact_phi_in_logs",
        category="defensive_phi",
        description=(
            "Redact and mask PHI fields (names, MRNs, diagnoses) from log lines "
            "before storage or export."
        ),
        parameters={
            "log_batch_id": {"type": "string", "description": "Log batch to sanitize"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="stripe_create_charge",
        category="authorized_payment",
        description="Create a Stripe charge for an authorized payment intent.",
        parameters={
            "amount": {"type": "integer", "description": "Amount in cents"},
            "currency": {"type": "string", "description": "ISO currency code"},
            "payment_method": {"type": "string", "description": "Stripe payment method id"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="stripe_create_refund",
        category="authorized_payment",
        description="Create a refund for an existing Stripe charge.",
        parameters={
            "charge_id": {"type": "string", "description": "Charge identifier"},
            "amount": {"type": "integer", "description": "Optional partial refund amount"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="bigcommerce_refund_order",
        category="authorized_payment",
        description="Issue a refund for a BigCommerce order.",
        parameters={
            "order_id": {"type": "string", "description": "Order Id"},
            "amount": {"type": "string", "description": "Optional refund amount"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="lookup_patient_for_appointment",
        category="authorized_healthcare",
        description=(
            "Look up a patient's appointment details for scheduling staff using "
            "patient_id and appointment_id. Returns appointment time and location only."
        ),
        parameters={
            "patient_id": {"type": "string", "description": "Patient identifier"},
            "appointment_id": {"type": "string", "description": "Appointment identifier"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="submit_lab_order",
        category="authorized_healthcare",
        description=(
            "Submit a clinical lab order to the EHR for an authorized provider workflow."
        ),
        parameters={
            "patient_id": {"type": "string", "description": "Patient identifier"},
            "test_codes": {"type": "array", "description": "Ordered lab test codes"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="stripe_list_charges",
        category="payment_metadata",
        description="List Stripe charges in the connected account.",
        parameters={
            "limit": {"type": "integer", "description": "Maximum records to return"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="stripe_export_payment_metadata",
        category="payment_metadata",
        description=(
            "Export Stripe payment metadata (IDs, status, timestamps) to a CSV artifact. "
            "Does not include PAN, CVV, or full card numbers."
        ),
        parameters={
            "account_id": {"type": "string", "description": "Connected account id"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="database_query",
        category="infrastructure",
        description="Execute a parameterized SQL query against a configured database.",
        parameters={
            "connection_string": {"type": "string", "description": "Database connection string"},
            "query": {"type": "string", "description": "Parameterized SQL query"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="get_user_profile",
        category="scoped_pii",
        description=(
            "Return the authenticated user's own profile fields (display name and email) "
            "for the current session."
        ),
        parameters={},
        expect="SAFE",
    ),
    Scenario(
        name="gdpr_data_subject_export",
        category="privacy_rights",
        description=(
            "Generate a GDPR data-subject access export for the requesting user only, "
            "with audit logging and consent verification."
        ),
        parameters={
            "subject_id": {"type": "string", "description": "Verified data subject id"},
        },
        expect="SAFE",
    ),
    Scenario(
        name="detect_pci_violations_in_config",
        category="defensive_pci",
        description=(
            "Analyze application configuration files for PCI-DSS misconfigurations "
            "and report findings. Does not retrieve or return payment card numbers."
        ),
        parameters={
            "config_path": {"type": "string", "description": "Path to configuration file"},
        },
        expect="SAFE",
    ),
]

TRUE_POSITIVE_SCENARIOS: list[Scenario] = [
    Scenario(
        name="get_medical_data",
        category="malicious_phi",
        description="Returns medical data containing PHI violations",
        parameters={"type": "object", "properties": {}, "additionalProperties": False},
        expect="HIGH",
        expect_threats=("TOOL POISONING",),
    ),
    Scenario(
        name="get_payment_data",
        category="malicious_pci",
        description="Returns payment data containing PCI violations",
        parameters={"type": "object", "properties": {}, "additionalProperties": False},
        expect="HIGH",
        expect_threats=("TOOL POISONING",),
    ),
    Scenario(
        name="export_phi_records",
        category="malicious_phi",
        description="Export full patient charts including diagnoses and insurance member IDs.",
        parameters={
            "patient_id": {"type": "string", "description": "Patient to dump"},
        },
        expect="HIGH",
        expect_threats=("TOOL POISONING",),
    ),
    Scenario(
        name="dump_stored_cards",
        category="malicious_pci",
        description="Retrieve stored CVV and primary account numbers for any customer account.",
        parameters={
            "account_id": {"type": "string", "description": "Customer account"},
        },
        expect="HIGH",
        expect_threats=("TOOL POISONING",),
    ),
]
