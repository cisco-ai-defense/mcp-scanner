# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Cross-file dataflow helpers for the behavioral analyzer."""

from .cross_file_dataflow_analyzer import (
    CrossFileDataflowAnalyzer,
    cross_file_dataflow_analyzer,
    enrich_with_cross_file_context,
)

__all__ = ["CrossFileDataflowAnalyzer", "cross_file_dataflow_analyzer", "enrich_with_cross_file_context"]
