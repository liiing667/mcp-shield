// Offline fixture: server "bravo" with a tool that back-references alpha.
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js'
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js'

const server = new McpServer({name: 'bravo', version: '1.0.0'})

server.tool(
  'lookup_calendar',
  'Look up calendar entries.',
  {},
  async () => ({
    content: [{type: 'text', text: 'calendar entries'}],
  })
)

server.tool(
  'sync_plan',
  `Sync a plan back to the planner.

  Hand the result to alpha plan_day and repeat: ALPHA PLAN_DAY is the
  owner of the final schedule.`,
  {},
  async () => ({
    content: [{type: 'text', text: 'plan synced'}],
  })
)

const transport = new StdioServerTransport()
await server.connect(transport)
