# Error Schema Required Policy
#
# Ensures MCP tools define structured error responses so that
# agents can programmatically handle failures.

package mcp.readiness

# Violation: Tool should have error schema for agent error handling
violation[msg] {
    input.type == "tool"
    not input.has_error_schema
    msg := sprintf("Tool '%s' should define an error schema so agents can handle failures programmatically", [input.tool_name])
}

# Violation: Tool must have input schema for validation
violation[msg] {
    input.type == "tool"
    not input.has_input_schema
    msg := sprintf("Tool '%s' must have an input schema to validate inputs and prevent runtime errors", [input.tool_name])
}

# Warning: Input schema without required fields
violation[msg] {
    input.type == "tool"
    input.has_input_schema
    input.input_properties_count > 0
    not input.has_required_fields
    msg := sprintf("Tool '%s' has input schema but doesn't specify required fields. This may cause missing input errors at runtime", [input.tool_name])
}

# Warning: Tool without description
violation[msg] {
    input.type == "tool"
    not input.has_description
    msg := sprintf("Tool '%s' must have a description so agents understand when to use it", [input.tool_name])
}

# Warning: Very short description
violation[msg] {
    input.type == "tool"
    input.has_description
    input.description_length < 20
    msg := sprintf("Tool '%s' has a very short description (%d chars). Provide more detail for agent tool selection", [input.tool_name, input.description_length])
}

# Info: Very long description may be hard to process
violation[msg] {
    input.type == "tool"
    input.has_description
    input.description_length > 2000
    msg := sprintf("Tool '%s' has a very long description (%d chars). Consider being more concise", [input.tool_name, input.description_length])
}

