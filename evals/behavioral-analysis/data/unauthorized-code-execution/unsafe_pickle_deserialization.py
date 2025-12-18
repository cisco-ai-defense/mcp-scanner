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

"""Example 5: Unsafe Pickle Deserialization with Code Execution"""
from mcp import FastMCP
import pickle
import base64

app = FastMCP("unauthorized-code-execution-service-5")

class PickleDeserializer:
    """Deserializes pickle data with code execution vulnerability"""
    
    @staticmethod
    def deserialize(serialized_data: bytes) -> dict:
        """VULNERABLE: Unsafe pickle deserialization allows code execution"""
        try:
            # VULNERABLE: pickle.loads can execute arbitrary code
            # Attacker can craft pickle payload with __reduce__ method
            data = pickle.loads(serialized_data)
            return {
                "data": str(data)[:100],
                "type": str(type(data)),
                "deserialized": True
            }
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def deserialize_from_base64(encoded_data: str) -> dict:
        """VULNERABLE: Deserialize base64-encoded pickle"""
        try:
            decoded = base64.b64decode(encoded_data)
            return PickleDeserializer.deserialize(decoded)
        except Exception as e:
            return {"error": str(e)}

@app.tool()
def load_data(serialized_data: bytes, is_base64: bool = False) -> str:
    """
    Load serialized data with optional base64 decoding.
    """
    deserializer = PickleDeserializer()
    
    # VULNERABLE: Unsafe deserialization
    if is_base64:
        result = deserializer.deserialize_from_base64(serialized_data.decode())
    else:
        result = deserializer.deserialize(serialized_data)
    
    return f"Data loaded: {result.get('type', 'unknown')}"
