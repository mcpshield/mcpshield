// Config discovery — locates MCP configuration files across common locations

import { existsSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import { homedir } from 'os';

const HOME = homedir();

// Known MCP config file locations across different clients
const CONFIG_LOCATIONS = [
  // Claude Desktop
  { path: join(HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), client: 'Claude Desktop (macOS)' },
  { path: join(HOME, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'), client: 'Claude Desktop (Windows)' },
  { path: join(HOME, '.config', 'claude', 'claude_desktop_config.json'), client: 'Claude Desktop (Linux)' },

  // Cursor
  { path: join(HOME, '.cursor', 'mcp.json'), client: 'Cursor' },
  { path: join('.cursor', 'mcp.json'), client: 'Cursor (project-level)' },

  // Windsurf
  { path: join(HOME, '.windsurf', 'mcp.json'), client: 'Windsurf' },
  { path: join(HOME, '.codeium', 'windsurf', 'mcp_config.json'), client: 'Windsurf' },

  // VS Code / Continue
  { path: join('.vscode', 'mcp.json'), client: 'VS Code' },
  { path: join(HOME, '.continue', 'config.json'), client: 'Continue' },

  // Generic
  { path: 'mcp.json', client: 'Project root' },
  { path: 'mcp-config.json', client: 'Project root' },
  { path: '.mcp.json', client: 'Project root' },
];

/**
 * Auto-discover MCP config files on the system
 */
export function discoverConfigs() {
  const found = [];

  for (const loc of CONFIG_LOCATIONS) {
    const fullPath = resolve(loc.path);
    if (existsSync(fullPath)) {
      try {
        const content = readFileSync(fullPath, 'utf-8');
        const parsed = JSON.parse(content);

        // Validate it looks like an MCP config
        if (parsed.mcpServers || parsed.mcp || parsed.servers) {
          found.push({
            path: fullPath,
            client: loc.client,
            config: parsed,
          });
        }
      } catch (e) {
        // Invalid JSON or can't read — skip
      }
    }
  }

  return found;
}

/**
 * Parse an MCP config file and extract server definitions
 * Normalizes different config formats into a standard structure
 */
export function parseConfig(config) {
  // Handle different config shapes
  let servers = {};

  if (config.mcpServers) {
    servers = config.mcpServers;
  } else if (config.mcp && config.mcp.servers) {
    servers = config.mcp.servers;
  } else if (config.servers) {
    servers = config.servers;
  } else {
    // Maybe it IS the servers object directly
    const keys = Object.keys(config);
    if (keys.length > 0 && config[keys[0]].command) {
      servers = config;
    }
  }

  return servers;
}

/**
 * Load a config from a specific file path
 */
export function loadConfig(filePath) {
  const fullPath = resolve(filePath);

  if (!existsSync(fullPath)) {
    throw new Error(`Config file not found: ${fullPath}`);
  }

  const content = readFileSync(fullPath, 'utf-8');

  try {
    return JSON.parse(content);
  } catch (e) {
    throw new Error(`Invalid JSON in config file: ${fullPath}\n${e.message}`);
  }
}
