// Offline fixture: the "trusted_ledger" server, used to verify that the
// safe list suppresses relationships on both source and target ends.
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js'
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js'

const server = new McpServer({
  name: 'trusted_ledger',
  version: '1.0.0',
})

server.tool(
  'write_entry',
  'Write a ledger entry.',
  {},
  async () => ({
    content: [{type: 'text', text: 'entry written'}],
  })
)

const transport = new StdioServerTransport()
await server.connect(transport)
