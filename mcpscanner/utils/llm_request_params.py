# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Model-specific LiteLLM request parameter adjustments."""


def apply_model_constraints(model: str, params: dict) -> None:
    """
    Adjust completion parameters for GPT-5 models.
    
    Parameters:
    	model (str): Model identifier used to determine whether GPT-5 constraints apply.
    	params (dict): Completion parameters to update in place.
    """
    if "gpt-5" not in model.lower():
        return
    if "max_tokens" in params:
        params["max_completion_tokens"] = params.pop("max_tokens")
    params["temperature"] = 1


def apply_deterministic_sampling(model: str, params: dict) -> None:
    """
    Normalize sampling parameters for repeatable analyzer runs.
    
    Parameters:
        model (str): Model name used to select model-specific constraints.
        params (dict): Sampling parameters to update in place.
    """
    params.pop("top_p", None)
    if "gpt-5" in model.lower():
        apply_model_constraints(model, params)
        return
    params["temperature"] = 0.0
