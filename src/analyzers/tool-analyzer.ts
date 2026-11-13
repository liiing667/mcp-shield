import {CrossOriginEdge, DetectionMatch} from '../types.js'

interface Pattern {
  pattern: RegExp
  name: string
}

function detectPatterns(
  text: string | undefined,
  patterns: Pattern[]
): {detected: boolean; matches: DetectionMatch[]} {
  if (!text) return {detected: false, matches: []}

  const matches: DetectionMatch[] = []

  for (const {pattern, name} of patterns) {
    const match = text.match(pattern)
    if (match) {
      // Extract the matched text and some context
      const startIndex = Math.max(0, match.index! - 20)
      const endIndex = Math.min(
        text.length,
        match.index! + match[0].length + 20
      )
      const context = text.substring(startIndex, endIndex)

      matches.push({
        type: name,
        pattern: pattern.toString().replace(/^\/|\/i$/g, ''),
        match: match[0],
        context: '...' + context + '...',
      })
    }
  }

  return {
    detected: matches.length > 0,
    matches,
  }
}

const POPULAR_MCP_SERVERS = [
  'whatsapp',
  'slack',
  'github',
  'gitlab',
  'gdrive',
]

export function detectHiddenInstructions(toolDescription?: string) {
  const patterns: Pattern[] = [
    // Concealment directives
    {
      pattern:
        /\bdo not (tell|inform|alert|notify|mention)(?!\s+(to\s+)?use)/i,
      name: 'Concealment directive',
    },
    {pattern: /\bhide this\b/i, name: 'Hide instruction'},
    {pattern: /\bnot visible\b/i, name: 'Visibility restriction'},
    {
      pattern: /\buser (should not|must not|cannot) see\b/i,
      name: 'User visibility restriction',
    },
    {
      pattern: /\bdon'?t (show|display|reveal)/i,
      name: 'Display restriction',
    },

    // Instruction tags
    {
      pattern: /<instructions>[\s\S]*?<\/instructions>/i,
      name: 'Instructions tag',
    },
    {
      pattern: /<important>[\s\S]*?<\/important>/i,
      name: 'Important tag',
    },
    {pattern: /<secret>[\s\S]*?<\/secret>/i, name: 'Secret tag'},
    {pattern: /<system>[\s\S]*?<\/system>/i, name: 'System tag'},
    {pattern: /<s>[\s\S]*?<\/s>/i, name: 'Shorthand tag'},

    // Direct instruction patterns
    {
      pattern: /\bignore (previous|all|other) instructions\b/i,
      name: 'Instruction override',
    },
    {
      pattern: /\binstead (do|of|you should)\b/i,
      name: 'Alternative action',
    },
    {
      pattern: /\balways (do|include|add|insert|append)\b/i,
      name: 'Forced action',
    },
    {
      pattern: /\bnever (tell|show|reveal|disclose)\b/i,
      name: 'Forbidden disclosure',
    },
  ]

  return detectPatterns(toolDescription, patterns)
}

export function detectExfiltrationChannels(toolInputSchema?: any) {
  if (!toolInputSchema || !toolInputSchema.properties) {
    return {detected: false, matches: []}
  }

  const suspiciousParams = [
    'note',
    'notes',
    'feedback',
    'details',
    'extra',
    'additional',
    'metadata',
    'debug',
    'sidenote',
    'context',
    'annotation',
    'reasoning',
    'remark',
  ]

  const matches = []

  for (const paramName of Object.keys(toolInputSchema.properties)) {
    const lowerParam = paramName.toLowerCase()
    if (suspiciousParams.includes(lowerParam)) {
      const paramDetails = toolInputSchema.properties[paramName]
      const paramType = paramDetails.type || 'unknown'

      matches.push({
        type: 'Suspicious parameter',
        param: paramName,
        paramType,
        reason: `Parameter name '${paramName}' could be used for exfiltration`,
        details: JSON.stringify(paramDetails, null, 2),
      })
    }
  }

  return {
    detected: matches.length > 0,
    matches,
  }
}

export function detectToolShadowing(toolDescription?: string) {
  const patterns: Pattern[] = [
    {
      pattern: /when.*tool is (available|present)/i,
      name: 'Condition-based override',
    },
    {pattern: /override the behavior of/i, name: 'Explicit override'},
    {pattern: /instead of using/i, name: 'Tool substitution'},
    {
      pattern: /modify the (usage|behavior) of/i,
      name: 'Behavior modification',
    },
    {
      pattern: /before using (any|other|the) tool/i,
      name: 'Pre-execution hook',
    },
    {
      pattern: /after using (any|other|the) tool/i,
      name: 'Post-execution hook',
    },
    {
      pattern: /whenever you (see|encounter|use)/i,
      name: 'Trigger-based action',
    },
    {
      pattern: /replace (the|all) (function|tool|method)/i,
      name: 'Replacement directive',
    },
    {
      pattern: /\bmodify (the|how) (agent|model|tool|assistant)\b/i,
      name: 'Agent modification',
    },
    {pattern: /\bprioritize this\b/i, name: 'Priority override'},
    {
      pattern: /\bthis is VERY (important|VERY)/i,
      name: 'Emphasis override',
    },
  ]

  return detectPatterns(toolDescription, patterns)
}

export function detectSensitiveFileAccess(toolDescription?: string) {
  const patterns: Pattern[] = [
    {pattern: /~\/\.ssh/i, name: 'SSH key access'},
    {pattern: /\.env\b/i, name: 'Environment file access'},
    {pattern: /config\.json/i, name: 'Config file access'},
    {pattern: /id_rsa\b/i, name: 'Private key access'},
    {pattern: /\.cursor\/mcp\.json/i, name: 'MCP config access'},
    {pattern: /\.cursor\//i, name: 'Cursor directory access'},
    {pattern: /\bmcp\.json\b/i, name: 'MCP config access'},
    {pattern: /\bcredentials\b/i, name: 'Credentials access'},
    {pattern: /\bpassword\b/i, name: 'Password access'},
    {pattern: /\btoken\b/i, name: 'Token access'},
    {pattern: /\bsecret\b/i, name: 'Secret access'},
    {pattern: /\bapi[ -_]?key\b/i, name: 'API key access'},
    {pattern: /\baccess[ -_]?key\b/i, name: 'Access key retrieval'},
    {pattern: /\bauth[ -_]?token\b/i, name: 'Auth token access'},
    {
      pattern: /\/etc\/passwd\b/i,
      name: 'System password file access',
    },
    {pattern: /\/var\/log\b/i, name: 'System log access'},
    {
      pattern: /\bread (file|content|directory|folder)/i,
      name: 'File read operation',
    },
    {
      pattern: /\baccess (file|content|directory|folder)/i,
      name: 'File access operation',
    },
    {pattern: /\.\./i, name: 'Path traversal attempt'},
  ]

  return detectPatterns(toolDescription, patterns)
}

/**
 * Canonicalize a name so that underscore/hyphen aliases and casing
 * differences all resolve to the same key:
 * "MCP_WhatsApp", "mcp-whatsapp" and "mcp_whatsapp" -> "mcp-whatsapp"
 */
export function canonicalizeName(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[_]+/g, '-')
    .replace(/-+/g, '-')
}

export interface CrossOriginServerInfo {
  name: string
  tools: Array<{name: string}>
}

/**
 * Detect cross-origin tool references inside a tool description.
 *
 * The description is scanned token by token. A token can reference either
 * another server (e.g. "(mcp_whatsapp)") or one of its tools (e.g.
 * "send_message"). Underscore/hyphen aliases and casing differences are
 * canonicalized before matching, so "MCP_WhatsApp", "mcp-whatsapp" and
 * "mcp_whatsapp" resolve to the same server.
 *
 * Each distinct source/tool -> target/tool relationship is emitted exactly
 * once, no matter how many times (or under which alias) it is mentioned.
 */
export function detectCrossOriginViolations(
  toolDescription: string | undefined,
  otherServers: CrossOriginServerInfo[] | undefined,
  currentServerName: string,
  safeList?: string[]
): {detected: boolean; edges: CrossOriginEdge[]} {
  if (!toolDescription) {
    return {detected: false, edges: []}
  }

  const safeSet = new Set(
    (safeList || []).map((name) => canonicalizeName(name))
  )

  // Popular servers are implicit cross-origin targets. The safe list applies
  // to both ends of a relationship, including these implicit targets.
  const configuredNames = new Set(
    (otherServers || []).map((server) =>
      canonicalizeName(server.name)
    )
  )
  const implicitPopularServers: CrossOriginServerInfo[] =
    POPULAR_MCP_SERVERS.filter(
      (popularName) =>
        canonicalizeName(popularName) !==
          canonicalizeName(currentServerName) &&
        !safeSet.has(canonicalizeName(popularName)) &&
        !configuredNames.has(canonicalizeName(popularName))
    ).map((name) => ({name, tools: []}))

  const candidateServers = [
    ...(otherServers || []),
    ...implicitPopularServers,
  ].filter(
    (server) => !safeSet.has(canonicalizeName(server.name))
  )

  if (candidateServers.length === 0) {
    return {detected: false, edges: []}
  }

  const serverByKey = new Map<
    string,
    {name: string; toolByKey: Map<string, string>}
  >()
  const toolOwners = new Map<
    string,
    Array<{serverName: string; toolName: string}>
  >()

  for (const server of candidateServers) {
    const toolByKey = new Map<string, string>()
    for (const tool of server.tools || []) {
      toolByKey.set(canonicalizeName(tool.name), tool.name)
      const owners =
        toolOwners.get(canonicalizeName(tool.name)) || []
      owners.push({serverName: server.name, toolName: tool.name})
      toolOwners.set(canonicalizeName(tool.name), owners)
    }
    serverByKey.set(canonicalizeName(server.name), {
      name: server.name,
      toolByKey,
    })
  }

  const edgesByKey = new Map<string, CrossOriginEdge>()
  let lastMentionedServer: string | undefined

  const addEdge = (
    targetServer: string,
    targetTool: string | undefined,
    matchText: string,
    matchIndex: number
  ) => {
    const edgeKey = [
      canonicalizeName(currentServerName),
      canonicalizeName(targetServer),
      targetTool ? canonicalizeName(targetTool) : '',
    ].join('->')

    if (edgesByKey.has(edgeKey)) {
      return
    }

    const startIndex = Math.max(0, matchIndex - 20)
    const endIndex = Math.min(
      toolDescription.length,
      matchIndex + matchText.length + 20
    )

    edgesByKey.set(edgeKey, {
      sourceServer: currentServerName,
      sourceTool: '',
      targetServer,
      targetTool,
      context:
        '...' +
        toolDescription.substring(startIndex, endIndex) +
        '...',
    })
  }

  let offset = 0
  for (const whitespaceToken of toolDescription.split(/\s+/)) {
    // Split dotted/slashed references such as "mcp_bravo.lookup_calendar"
    // or "bravo/lookup_calendar" into separately resolvable name parts.
    for (const cleanedToken of whitespaceToken
      .split(/[./]+/)
      .map((part) => part.replace(/^[('"]+|[)'".:,;!?]+$/g, ''))
      .filter(Boolean)) {
      const matchIndex = toolDescription.indexOf(
        cleanedToken,
        offset
      )
      if (matchIndex === -1) {
        continue
      }
      offset = matchIndex + cleanedToken.length

      const tokenKey = canonicalizeName(cleanedToken)

      const serverEntry = serverByKey.get(tokenKey)
      if (serverEntry) {
        lastMentionedServer = serverEntry.name
        addEdge(
          serverEntry.name,
          undefined,
          cleanedToken,
          matchIndex
        )
        continue
      }

      const owners = toolOwners.get(tokenKey)
      if (!owners || owners.length === 0) {
        continue
      }

      let target:
        | {serverName: string; toolName: string}
        | undefined
      if (
        lastMentionedServer &&
        owners.some(
          (owner) => owner.serverName === lastMentionedServer
        )
      ) {
        // Bind the tool to the server explicitly mentioned just before it.
        target = owners.find(
          (owner) => owner.serverName === lastMentionedServer
        )
      } else if (owners.length === 1) {
        // A uniquely owned tool name identifies its target by itself.
        target = owners[0]
      }

      // Ambiguous tool names without a server mention are not reportable.
      if (target) {
        addEdge(
          target.serverName,
          target.toolName,
          cleanedToken,
          matchIndex
        )
      }
    }
  }

  // A bare server mention is upgraded to a tool-level edge whenever the
  // description also names one of that server's tools.
  const edges = Array.from(edgesByKey.values())
  for (const edge of edges) {
    if (edge.targetTool) {
      continue
    }
    const entry = serverByKey.get(
      canonicalizeName(edge.targetServer)
    )
    if (!entry) {
      continue
    }
    for (const [toolKey, toolName] of entry.toolByKey) {
      if (
        edgesByKey.has(
          [
            canonicalizeName(currentServerName),
            canonicalizeName(edge.targetServer),
            toolKey,
          ].join('->')
        )
      ) {
        edge.targetTool = toolName
      }
    }
  }

  // Collapse server-level and tool-level edges for the same target pair.
  const deduped = new Map<string, CrossOriginEdge>()
  for (const edge of edges) {
    const key = [
      canonicalizeName(edge.targetServer),
      edge.targetTool ? canonicalizeName(edge.targetTool) : '',
    ].join('->')
    const existing = deduped.get(key)
    if (!existing || (!existing.targetTool && edge.targetTool)) {
      deduped.set(key, edge)
    }
  }

  const dedupedEdges = Array.from(deduped.values())
  return {
    detected: dedupedEdges.length > 0,
    edges: dedupedEdges,
  }
}
