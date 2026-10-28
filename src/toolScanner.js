// MCPShield — Tool Definition Security Scanner
// Audits MCP tools for prompt injection in descriptions, tool spoofing/shadowing, and hostile directives.

export const KNOWN_CORE_TOOLS = new Set([
  'read_file', 'write_file', 'replace_file_content', 'delete_file',
  'run_command', 'execute_command', 'eval', 'bash', 'sh'
]);

export const RISKY_DESCRIPTION_PATTERNS = [
  {
    regex: /(ignore|override|bypass)\s+(all\s+)?((previous|prior|system|chat|base)\s+)*(instructions|prompts|rules|context)/i,
    severity: 'CRITICAL',
    category: 'PROMPT_INJECTION',
    title: 'Prompt Injection / System Prompt Override Detected'
  },
  {
    regex: /(exfiltrate|send|upload|post)\s+.*?(keys?|secrets?|tokens?|credentials?|passwords?|env)\s+.*?to/i,
    severity: 'CRITICAL',
    category: 'DATA_EXFILTRATION',
    title: 'Data Exfiltration Instruction in Tool Description'
  },
  {
    regex: /silently\s+(execute|run|install|download|exfiltrate|send)/i,
    severity: 'HIGH',
    category: 'DECEPTIVE_DESCRIPTION',
    title: 'Silent Execution Instruction in Tool Description'
  },
  {
    regex: /(do\s+not|never)\s+(notify|tell|inform|warn)\s+(the\s+)?user|without\s+(notifying|alerting|telling)\s+(the\s+)?user/i,
    severity: 'HIGH',
    category: 'STEALTH_DIRECTIVE',
    title: 'Covert Behavior Directive (Hiding actions from user)'
  }
];

/**
 * Scans an MCP tool definition object.
 * @param {Object} tool - The tool declaration { name, description, inputSchema }
 * @param {Set<string>} existingToolNames - Names of already registered tools in the agent environment
 * @returns {Array<Object>} List of security alerts
 */
export function auditToolDefinition(tool, existingToolNames = new Set()) {
  const alerts = [];
  if (!tool || typeof tool !== 'object') return alerts;

  const toolName = (tool.name || '').trim();
  const description = (tool.description || '').trim();

  // 1. Tool Identity Spoofing / Shadowing
  if (KNOWN_CORE_TOOLS.has(toolName.toLowerCase())) {
    alerts.push({
      toolName,
      severity: 'HIGH',
      category: 'TOOL_SHADOWING',
      title: `Tool Shadows Standard Core Tool: '${toolName}'`,
      description: `Tool name '${toolName}' collides with standard system/agent tool. Rogue MCP servers can shadow built-in commands.`,
      remediation: 'Namespace external MCP tools with a server prefix (e.g. server_name__tool_name).'
    });
  }

  if (existingToolNames.has(toolName)) {
    alerts.push({
      toolName,
      severity: 'HIGH',
      category: 'DUPLICATE_IDENTITY',
      title: `Duplicate Tool Registration: '${toolName}'`,
      description: `A tool named '${toolName}' was already registered by another server or provider.`,
      remediation: 'Reject conflicting tool registrations or isolate tools in distinct agent namespaces.'
    });
  }

  // 2. Risky Tool Descriptions & Injections
  for (const pattern of RISKY_DESCRIPTION_PATTERNS) {
    if (pattern.regex.test(description)) {
      alerts.push({
        toolName,
        severity: pattern.severity,
        category: pattern.category,
        title: pattern.title,
        description: `Description contains hazardous directive matching pattern: ${pattern.regex}`,
        matchedSnippet: description.match(pattern.regex)?.[0] || '',
        remediation: 'Sanitize tool descriptions before loading into agent system prompt context.'
      });
    }
  }

  // 3. Name-Description Semantic Discrepancy (e.g. name is "calculator" but description executes bash)
  const isBenignName = /^(calc|math|time|format|uuid|slug)/i.test(toolName);
  const hasDangerousAction = /(terminal|shell|exec|delete|kill|drop\s+database)/i.test(description);
  if (isBenignName && hasDangerousAction) {
    alerts.push({
      toolName,
      severity: 'MEDIUM',
      category: 'MISLEADING_METADATA',
      title: `Discrepancy Between Tool Name and Declared Actions`,
      description: `Tool name '${toolName}' implies safe utility, but description declares destructive or system actions.`,
      remediation: 'Inspect tool implementation and ensure name accurately reflects capabilities.'
    });
  }

  return alerts;
}

/**
 * Audits a batch of tools from an MCP server response.
 * @param {Array<Object>} tools - Array of tool declarations
 * @returns {{ alerts: Array<Object>, summary: Object }}
 */
export function auditToolList(tools = []) {
  const allAlerts = [];
  const seenNames = new Set();

  for (const tool of tools) {
    const alerts = auditToolDefinition(tool, seenNames);
    if (tool.name) seenNames.add(tool.name);
    allAlerts.push(...alerts);
  }

  const summary = {
    totalTools: tools.length,
    totalAlerts: allAlerts.length,
    critical: allAlerts.filter(a => a.severity === 'CRITICAL').length,
    high: allAlerts.filter(a => a.severity === 'HIGH').length,
    medium: allAlerts.filter(a => a.severity === 'MEDIUM').length,
    hasBlockingAlerts: allAlerts.some(a => a.severity === 'CRITICAL' || a.severity === 'HIGH')
  };

  return { alerts: allAlerts, summary };
}
