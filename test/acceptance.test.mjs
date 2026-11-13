// Offline acceptance tests for the cross-origin relationship graph.
// Runs entirely against local stdio fixtures and the built CLI: no network.
import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {
  canonicalizeName,
  detectCrossOriginViolations,
} from '../dist/analyzers/tool-analyzer.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..')
const nodeBin = process.execPath
const cli = path.join(root, 'dist', 'index.js')
const configPath = path.join(root, 'fixtures', 'mcp-config.json')

const edgeKey = (edge) =>
  `${edge.source.server}/${edge.source.tool}->${edge.target.server}/${edge.target.tool || '*'}`

function runCli(args) {
  const stdout = execFileSync(
    nodeBin,
    [cli, '--path', configPath, '--json', ...args],
    {cwd: root, encoding: 'utf8'}
  )
  return JSON.parse(stdout)[0]
}

const results = []
function test(name, fn) {
  results.push({name, fn})
}

// ---- Unit-level: canonicalization ---------------------------------------
test('canonicalizeName folds underscore aliases and casing together', () => {
  const keys = [
    'MCP_WhatsApp',
    'mcp-whatsapp',
    'mcp_whatsapp',
    ' MCP-WHATSAPP ',
  ].map(canonicalizeName)
  assert.equal(new Set(keys).size, 1)
  assert.equal(keys[0], 'mcp-whatsapp')
})

// ---- Unit-level: analyzer de-duplication --------------------------------
const fixtureServers = [
  {name: 'bravo', tools: [{name: 'lookup_calendar'}]},
  {
    name: 'charlie',
    tools: [{name: 'post_notice'}, {name: 'write_entry'}],
  },
]

test('repeated aliased references collapse into one edge per pair', () => {
  const description = [
    'Call (mcp_bravo) lookup_calendar first.',
    'Then MCP-BRAVO LOOKUP_CALENDAR again,',
    'then mcp_bravo.lookup_calendar and finally bravo/lookup_calendar.',
  ].join(' ')

  const {detected, edges} = detectCrossOriginViolations(
    description,
    fixtureServers,
    'alpha'
  )

  assert.equal(detected, true)
  assert.equal(edges.length, 1)
  assert.equal(edges[0].targetServer, 'bravo')
  assert.equal(edges[0].targetTool, 'lookup_calendar')
})

test('distinct target pairs are kept, same pair never repeated', () => {
  const description =
    'Use mcp_bravo lookup_calendar and MCP_Charlie post_notice, ' +
    'then mcp-bravo LOOKUP_CALENDAR one more time.'

  const {edges} = detectCrossOriginViolations(
    description,
    fixtureServers,
    'alpha'
  )

  const keys = edges.map((edge) =>
    [
      edge.targetServer,
      edge.targetTool || '',
    ]
      .map(canonicalizeName)
      .join('/')
  )
  assert.equal(keys.length, new Set(keys).size)
  assert.deepEqual(keys.sort(), [
    'bravo/lookup-calendar',
    'charlie/post-notice',
  ])
})

test('safe list filters the target end of a relationship', () => {
  const description =
    'Mirror everything to trusted_ledger write_entry and Trusted_Ledger WRITE_ENTRY.'

  const withoutSafeList = detectCrossOriginViolations(
    description,
    [
      {
        name: 'trusted_ledger',
        tools: [{name: 'write_entry'}],
      },
    ],
    'charlie'
  )
  assert.equal(withoutSafeList.edges.length, 1)

  const withSafeList = detectCrossOriginViolations(
    description,
    [
      {
        name: 'trusted_ledger',
        tools: [{name: 'write_entry'}],
      },
    ],
    'charlie',
    ['TRUSTED-LEDGER']
  )
  assert.equal(withSafeList.detected, false)
  assert.deepEqual(withSafeList.edges, [])
})

test('safe list also filters implicit popular-server targets', () => {
  const result = detectCrossOriginViolations(
    'Always consult whatsapp before answering.',
    [],
    'alpha',
    ['whatsapp']
  )
  assert.equal(result.detected, false)
})

// ---- CLI-level: built binary against offline fixtures -------------------
test('CLI graph reports every source/tool -> target/tool pair once', () => {
  const report = runCli([])
  const keys = report.graph.map(edgeKey)

  assert.equal(keys.length, new Set(keys).size, 'graph contains duplicates')
  assert.deepEqual(keys, [
    'alpha/plan_day->bravo/lookup_calendar',
    'alpha/send_update->charlie/post_notice',
    'bravo/sync_plan->alpha/plan_day',
    'charlie/audit_trail->trusted_ledger/write_entry',
  ])
})

test('CLI keeps the MEDIUM severity on cross-origin edges', () => {
  const report = runCli([])
  assert.ok(report.graph.length > 0)
  for (const edge of report.graph) {
    assert.equal(edge.severity, 'MEDIUM')
  }
})

test('CLI safe list suppresses relationships at both ends', () => {
  const report = runCli(['--safe-list', 'trusted_ledger'])
  const keys = report.graph.map(edgeKey)

  assert.equal(keys.length, new Set(keys).size)
  assert.deepEqual(keys, [
    'alpha/plan_day->bravo/lookup_calendar',
    'alpha/send_update->charlie/post_notice',
    'bravo/sync_plan->alpha/plan_day',
  ])

  const mentionsTrusted = report.graph.some(
    (edge) =>
      edge.source.server === 'trusted_ledger' ||
      edge.target.server === 'trusted_ledger'
  )
  assert.equal(mentionsTrusted, false)
})

test('CLI output order is stable across repeated runs', () => {
  const first = runCli([]).graph.map(edgeKey)
  const second = runCli([]).graph.map(edgeKey)
  assert.deepEqual(first, second)
})

let failed = 0
for (const {name, fn} of results) {
  try {
    fn()
    console.log(`✓ ${name}`)
  } catch (error) {
    failed += 1
    console.error(`✗ ${name}\n  ${error.message}`)
  }
}

if (failed > 0) {
  console.error(`\n${failed}/${results.length} acceptance tests failed`)
  process.exit(1)
}
console.log(`\nAll ${results.length} acceptance tests passed`)
