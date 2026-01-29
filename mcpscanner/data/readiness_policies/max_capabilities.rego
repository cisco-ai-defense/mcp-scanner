# Maximum Capabilities Policy
#
# Ensures MCP tools don't have an excessive number of capabilities,
# which would indicate overloaded scope and reduce reliability.

package mcp.readiness

# Maximum recommended capabilities per tool
default max_capabilities = 10

# Maximum recommended input parameters
default max_input_parameters = 15

# Violation: Too many capabilities
violation[msg] {
    input.type == "tool"
    input.capabilities_count > max_capabilities
    msg := sprintf("Tool '%s' has %d capabilities, exceeding the recommended maximum of %d. Consider splitting into focused tools", [input.tool_name, input.capabilities_count, max_capabilities])
}

# Warning: Many capabilities approaching limit
violation[msg] {
    input.type == "tool"
    input.capabilities_count > 7
    input.capabilities_count <= max_capabilities
    msg := sprintf("Tool '%s' has %d capabilities, approaching the recommended limit. Consider if all are necessary", [input.tool_name, input.capabilities_count])
}

# Warning: Too many input parameters
violation[msg] {
    input.type == "tool"
    input.input_properties_count > max_input_parameters
    msg := sprintf("Tool '%s' has %d input parameters, exceeding the recommended maximum of %d. This may indicate overloaded scope", [input.tool_name, input.input_properties_count, max_input_parameters])
}

# Info: Many input parameters
violation[msg] {
    input.type == "tool"
    input.input_properties_count > 10
    input.input_properties_count <= max_input_parameters
    msg := sprintf("Tool '%s' has %d input parameters. Consider if all are necessary or if the tool should be split", [input.tool_name, input.input_properties_count])
}

