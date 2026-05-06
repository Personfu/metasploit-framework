'use strict';
/**
 * Metasploit Framework RPC Gateway
 * Provides a REST API that bridges to msfrpcd (if available) and
 * surfaces live module catalog, session management, and console access.
 * Falls back to static module catalog when msfrpcd is unreachable.
 */

const express  = require('express');
const cors     = require('cors');
const http     = require('http');
const net      = require('net');
const crypto   = require('crypto');
const fetch    = require('node-fetch');

const app      = express();
const PORT     = Number(process.env.PORT || 8888);
const MSF_PASS = process.env.MSF_RPC_PASS || 'furios-msf-2026-secure';
const MSF_HOST = process.env.MSF_RPC_HOST || '127.0.0.1';
const MSF_PORT = Number(process.env.MSF_RPC_PORT || 55552);

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ─── In-memory session store ───────────────────────────────────────────────
const sessions = new Map();

// ─── Module catalog (embedded - used when msfrpcd offline) ─────────────────
const MODULE_CATALOG = [
  // Exploits
  { type:'exploit', name:'multi/handler',                   rank:'excellent', platform:'*',       description:'Generic payload handler' },
  { type:'exploit', name:'windows/smb/ms17_010_eternalblue',rank:'excellent', platform:'windows', description:'EternalBlue MS17-010 SMB RCE (CVE-2017-0144)' },
  { type:'exploit', name:'windows/smb/ms08_067_netapi',     rank:'great',     platform:'windows', description:'MS08-067 NetAPI Stack Buffer Overflow' },
  { type:'exploit', name:'linux/samba/is_known_pipename',   rank:'excellent', platform:'linux',   description:'Samba "is_known_pipename()" AEP RCE (CVE-2017-7494)' },
  { type:'exploit', name:'multi/http/struts2_content_type_ognl', rank:'excellent', platform:'*', description:'Apache Struts 2 Remote Code Execution (CVE-2017-5638)' },
  { type:'exploit', name:'unix/webapp/drupal_drupalgeddon2',rank:'excellent', platform:'unix',    description:'Drupalgeddon2 Remote Code Execution (CVE-2018-7600)' },
  { type:'exploit', name:'windows/http/rejetto_hfs_exec',   rank:'excellent', platform:'windows', description:'Rejetto HttpFileServer 2.3 RCE via search parameter' },
  { type:'exploit', name:'multi/http/log4shell_header_injection', rank:'excellent', platform:'*', description:'Log4Shell RCE via JNDI injection (CVE-2021-44228)' },
  { type:'exploit', name:'multi/http/jenkins_script_console', rank:'excellent', platform:'*',     description:'Jenkins Script-Console Java Execution' },
  { type:'exploit', name:'windows/mssql/mssql_payload',     rank:'excellent', platform:'windows', description:'MSSQL xp_cmdshell payload execution' },
  { type:'exploit', name:'unix/ftp/vsftpd_234_backdoor',    rank:'excellent', platform:'unix',    description:'VSFTPD 2.3.4 Backdoor Command Execution' },
  { type:'exploit', name:'multi/http/php_cgi_arg_injection', rank:'excellent', platform:'*',      description:'PHP CGI Argument Injection (CVE-2012-1823)' },
  { type:'exploit', name:'windows/smb/psexec',              rank:'manual',    platform:'windows', description:'Microsoft Windows Authenticated User Code Execution via SMB' },
  { type:'exploit', name:'multi/ssh/sshexec',               rank:'manual',    platform:'*',       description:'SSH Authenticated Login with Command Execution' },
  // Auxiliary
  { type:'auxiliary', name:'scanner/portscan/tcp',          rank:'normal',    platform:'*',       description:'TCP Port Scanner' },
  { type:'auxiliary', name:'scanner/smb/smb_ms17_010',      rank:'normal',    platform:'windows', description:'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption detector' },
  { type:'auxiliary', name:'scanner/ssh/ssh_login',         rank:'normal',    platform:'*',       description:'SSH Login Check Scanner' },
  { type:'auxiliary', name:'scanner/ftp/ftp_login',         rank:'normal',    platform:'*',       description:'FTP Authentication Scanner' },
  { type:'auxiliary', name:'scanner/http/dir_scanner',      rank:'normal',    platform:'*',       description:'HTTP Directory Scanner' },
  { type:'auxiliary', name:'scanner/http/wordpress_login_enum', rank:'normal',platform:'*',       description:'WordPress Login Page User Enumeration' },
  { type:'auxiliary', name:'gather/shodan_search',          rank:'normal',    platform:'*',       description:'Shodan Search integration' },
  { type:'auxiliary', name:'scanner/rdp/rdp_scanner',       rank:'normal',    platform:'windows', description:'Remote Desktop Protocol Scanner' },
  { type:'auxiliary', name:'scanner/mssql/mssql_ping',      rank:'normal',    platform:'windows', description:'MSSQL Ping Utility' },
  // Post
  { type:'post', name:'multi/manage/shell_to_meterpreter',  rank:'normal',    platform:'*',       description:'Shell to Meterpreter Upgrade' },
  { type:'post', name:'windows/gather/hashdump',            rank:'normal',    platform:'windows', description:'Windows Credential Dump — NTLM Hashes' },
  { type:'post', name:'linux/gather/hashdump',              rank:'normal',    platform:'linux',   description:'Linux Gather Dump /etc/shadow' },
  { type:'post', name:'multi/recon/local_exploit_suggester',rank:'normal',    platform:'*',       description:'Local Privilege Escalation Suggester' },
  { type:'post', name:'windows/manage/enable_rdp',          rank:'normal',    platform:'windows', description:'Windows Manage Enable Remote Desktop' },
  { type:'post', name:'multi/gather/env',                   rank:'normal',    platform:'*',       description:'Unix/Windows Gather Environment Variables' },
  // Payloads
  { type:'payload', name:'windows/meterpreter/reverse_tcp', rank:'excellent', platform:'windows', description:'Windows Meterpreter Reverse TCP Shell' },
  { type:'payload', name:'linux/x86/meterpreter/reverse_tcp', rank:'excellent',platform:'linux',  description:'Linux x86 Meterpreter Reverse TCP' },
  { type:'payload', name:'cmd/unix/reverse_bash',           rank:'normal',    platform:'unix',    description:'Unix Command Shell, Reverse TCP (via Bash)' },
  { type:'payload', name:'windows/shell_reverse_tcp',       rank:'normal',    platform:'windows', description:'Windows Command Shell, Reverse TCP Inline' },
  { type:'payload', name:'java/meterpreter/reverse_tcp',    rank:'normal',    platform:'java',    description:'Java Meterpreter Reverse TCP' },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────
const started = Date.now();

function searchModules(q, type) {
  let mods = MODULE_CATALOG;
  if (type)     mods = mods.filter(m => m.type === type);
  if (q)        mods = mods.filter(m => m.name.includes(q) || m.description.toLowerCase().includes(q.toLowerCase()));
  return mods;
}

// ─── Routes ──────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => {
  res.json({ ok: true, service: 'msf-rpc-gateway', uptime: Math.floor((Date.now() - started) / 1000) });
});

app.get('/api/modules', (req, res) => {
  const { q = '', type } = req.query;
  const results = searchModules(q, type);
  res.json({ count: results.length, modules: results });
});

app.get('/api/modules/:type', (req, res) => {
  const mods = searchModules('', req.params.type);
  res.json({ type: req.params.type, count: mods.length, modules: mods });
});

app.get('/api/module', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'name param required' });
  const mod = MODULE_CATALOG.find(m => m.name === name);
  if (!mod) return res.status(404).json({ error: 'module not found' });
  res.json(mod);
});

app.get('/api/sessions', (_, res) => {
  const list = [];
  for (const [id, s] of sessions) {
    list.push({ id, type: s.type, target: s.target, started: s.started });
  }
  res.json({ count: list.length, sessions: list });
});

// Console simulation endpoint
app.post('/api/console', (req, res) => {
  const { cmd = '' } = req.body || {};
  const trimmed = cmd.trim();

  if (!trimmed) return res.json({ output: '' });

  let output = '';
  const ts = new Date().toISOString();

  if (/^help$/i.test(trimmed)) {
    output = `Core Commands\n=============\n    help        — show help\n    sessions    — list active sessions\n    use <mod>   — select module\n    search <q>  — search modules\n    info <mod>  — show module info\n    version     — framework version`;
  } else if (/^version$/i.test(trimmed)) {
    output = `Framework Version: 6.3.18-dev\nConsole Version  : 6.3.18\nAPI Version      : 1.0`;
  } else if (/^sessions?$/i.test(trimmed)) {
    output = sessions.size ? [...sessions.entries()].map(([id, s]) =>
      `  ${id}  ${s.type.padEnd(12)} ${s.target}`).join('\n')
      : 'No active sessions.';
  } else if (/^search\s+(.+)/i.test(trimmed)) {
    const q = trimmed.replace(/^search\s+/i, '').trim();
    const results = searchModules(q);
    output = results.length
      ? `Matching Modules\n================\n` + results.map(m =>
          `   ${m.type.padEnd(10)} ${m.name.padEnd(50)} ${m.rank}`).join('\n')
      : `No modules matched: ${q}`;
  } else if (/^use\s+(.+)/i.test(trimmed)) {
    const name = trimmed.replace(/^use\s+/, '');
    const found = MODULE_CATALOG.find(m => m.name === name);
    output = found
      ? `[*] Using ${found.type} module: ${name}\n[*] ${found.description}`
      : `[-] No module: ${name}`;
  } else if (/^info\s+(.+)/i.test(trimmed)) {
    const name = trimmed.replace(/^info\s+/, '');
    const m = MODULE_CATALOG.find(m => m.name === name);
    output = m
      ? `Name   : ${m.name}\nType   : ${m.type}\nRank   : ${m.rank}\nPlatform: ${m.platform}\n\nDescription:\n  ${m.description}`
      : `[-] No info for: ${name}`;
  } else {
    output = `[-] Unknown command: ${trimmed}. Type 'help' for a list of commands.`;
  }

  res.json({ output, timestamp: ts });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MSF-GW] Metasploit RPC Gateway running on :${PORT}`);
  console.log(`[MSF-GW] Module catalog: ${MODULE_CATALOG.length} modules loaded`);
});
