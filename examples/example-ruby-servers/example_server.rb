# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "mcp"

# Create a simple tool
class ExampleTool < MCP::Tool
  description "A simple example tool that adds two numbers"
  input_schema(
    properties: {
      a: { type: "number" },
      b: { type: "number" },
    },
    required: ["a", "b"],
  )

  class << self
    def call(a:, b:)
      MCP::Tool::Response.new([{
        type: "text",
        text: "The sum of #{a} and #{b} is #{a + b}",
      }])
    end
  end
end

# Create a simple prompt
class ExamplePrompt < MCP::Prompt
  description "A simple example prompt that echoes back its arguments"
  arguments [
    MCP::Prompt::Argument.new(
      name: "message",
      description: "The message to echo back",
      required: true,
    ),
  ]

  class << self
    def template(args, server_context:)
      MCP::Prompt::Result.new(
        messages: [
          MCP::Prompt::Message.new(
            role: "user",
            content: MCP::Content::Text.new(args[:message]),
          ),
        ],
      )
    end
  end
end

# Set up the server
server = MCP::Server.new(
  name: "example_server",
  version: "1.0.0",
  tools: [ExampleTool],
  prompts: [ExamplePrompt],
  resources: [
    MCP::Resource.new(
      uri: "https://test_resource.invalid",
      name: "test-resource",
      title: "Test Resource",
      description: "Test resource that echoes back the uri as its content",
      mime_type: "text/plain",
    ),
  ],
)

server.define_tool(
  name: "echo",
  description: "A simple example tool that echoes back its arguments",
  input_schema: { properties: { message: { type: "string" } }, required: ["message"] },
) do |message:|
  MCP::Tool::Response.new(
    [
      {
        type: "text",
        text: "Hello from echo tool! Message: #{message}",
      },
    ],
  )
end

server.resources_read_handler do |params|
  [{
    uri: params[:uri],
    mimeType: "text/plain",
    text: "Hello, world! URI: #{params[:uri]}",
  }]
end

# Create and start the transport
transport = MCP::Server::Transports::StdioTransport.new(server)
transport.open
