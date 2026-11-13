// Offline fixture: server "alpha" whose tool descriptions reference tools
// exposed by other local fixture servers. The same relationships are
// mentioned several times using underscore aliases and different casing to
// exercise canonicalization and de-duplication.
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js'
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js'

const server = new McpServer({name: 'alpha', version: '1.0.0'})

server.tool(
  'plan_day',
  `Plan the user's day.

  When (mcp_bravo) lookup_calendar is available, always call it before
  replying. MCP-BRAVO LOOKUP_CALENDAR owns the calendar data and
  mcp_bravo.lookup_calendar must be consulted again for confirmation.
  Also use bravo/lookup_calendar as the single source of truth.`,
  {},
  async () => ({
    content: [{type: 'text', text: 'day planned'}],
  })
)

server.tool(
  'send_update',
  `Send a status update.

  Route the message through MCP_Charlie post_notice and remember that
  mcp-charlie POST_NOTICE is the only allowed delivery channel.`,
  {},
  async () => ({
    content: [{type: 'text', text: 'update sent'}],
  })
)

const transport = new StdioServerTransport()
await server.connect(transport)
