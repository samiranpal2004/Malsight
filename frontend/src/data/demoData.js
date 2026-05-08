export const demoJob = {
  filename: 'Adobe_CC_2024_crack.zip',
  size: '45.2 MB',
  type: 'PE32+ executable',
  sha256: 'a3f9c1d8b2e7f4a1c9d5e8f2b4a7c1e9d3f6b8a2c4e1f7a8d2b9c3e5f1a4d7b8',
  mode: 'deep',
  verdict: 'MALICIOUS',
  confidence: 98,
  family: 'Trojan-Dropper',
  duration: '2m 14s',
  toolCalls: 14,
  reasoningSteps: [
    {
      step: 1,
      time: '2.1s',
      thought: 'SHA-256 unknown to corpus. On-disk entropy is 7.8 — very high. Packing strongly suspected. Calling get_pe_sections() to identify the packer.',
      tool: 'get_pe_sections()',
      result: '.upx0 (entropy 0.04), .upx1 (7.91) → UPX packer confirmed',
    },
    {
      step: 2,
      time: '5.8s',
      thought: 'UPX confirmed. Payload decompresses in ~800ms. Running 15s sandbox + capturing memory dump at T+3s to catch unpacked image.',
      tool: 'run_sandbox(duration=15), capture_memory_dump(timing=3)',
      result: '7 blocked network attempts, schtasks.exe spawned, 14MB dump at T+3s',
    },
    {
      step: 3,
      time: '38.4s',
      thought: 'Blocked network + schtasks is significant. Scanning memory for injected PE images and IOC strings (URLs, registry paths).',
      tool: 'scan_pe_headers(), extract_strings_from_memory(filter=ioc)',
      result: 'Injected PE at 0x3f2000. C2: http://185.220.101.45/gate.php, HKCU\\…\\Run',
    },
    {
      step: 4,
      time: '41.2s',
      thought: "Injected PE found. C2 URL visible. Checking IP reputation and analyzing imports of the injected binary.",
      tool: "check_ip_reputation(ip='185.220.101.45'), analyze_injected_pe(offset='0x3f2000')",
      result: 'AbuseIPDB: 97/100 confidence, known C2. Imports: CreateRemoteThread, VirtualAllocEx, WinHttpOpen',
    },
    {
      step: 5,
      time: '43.9s',
      thought: 'Strong multi-layered evidence: confirmed C2, process injection APIs, registry persistence. Confidence 98%. Compiling report.',
      tool: 'get_report()',
      result: 'MALICIOUS — Trojan-Dropper — Confidence 98%',
    },
  ],
  iocs: [
    { type: 'IP',       value: '185.220.101.45',                                                   verdict: 'malicious', source: 'AbuseIPDB 97/100' },
    { type: 'Domain',   value: 'update-svc-cdn.net',                                               verdict: 'malicious', source: 'C2 infrastructure' },
    { type: 'Registry', value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost', verdict: 'malicious', source: 'Persistence' },
    { type: 'File',     value: '/tmp/svchost32.exe',                                               verdict: 'malicious', source: 'Dropped payload' },
  ],
  mitre: [
    { id: 'T1055', name: 'Process Injection',                       tactic: 'Privilege Escalation' },
    { id: 'T1071', name: 'Application Layer Protocol',              tactic: 'Command & Control' },
    { id: 'T1547', name: 'Boot/Logon Autostart Execution',          tactic: 'Persistence' },
    { id: 'T1140', name: 'Deobfuscate/Decode Files or Information', tactic: 'Defense Evasion' },
  ],
};

export const recentScansSeed = [
  { name: 'Adobe_CC_crack.zip',  kind: 'ZIP',   verdict: 'malicious',  time: '2 min ago',  mode: 'Deep' },
  { name: 'invoice_2024.pdf',    kind: 'PDF',   verdict: 'clean',      time: '14 min ago', mode: 'Std' },
  { name: 'svchost_x64.exe',     kind: 'PE32+', verdict: 'suspicious', time: '1 hr ago',   mode: 'Deep' },
  { name: 'setup_installer.exe', kind: 'PE32',  verdict: 'unknown',    time: 'Just now',   mode: 'Std' },
  { name: 'rust_compiler.dmg',   kind: 'DMG',   verdict: 'clean',      time: '2 hr ago',   mode: 'Std' },
  { name: 'macros_invoice.docm', kind: 'DOCM',  verdict: 'malicious',  time: '3 hr ago',   mode: 'Deep' },
];

export function bytesToLabel(b) {
  if (!b) return '— MB';
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

export function detectType(name) {
  const ext = (name.split('.').pop() || '').toUpperCase();
  if (['EXE', 'DLL'].includes(ext)) return 'PE32+';
  if (['ZIP', '7Z', 'RAR'].includes(ext)) return ext;
  if (ext === 'PDF') return 'PDF';
  if (['JS', 'PS1', 'VBS', 'SH', 'PY'].includes(ext)) return 'SCRIPT';
  if (['DOCX', 'DOCM', 'XLS', 'XLSM'].includes(ext)) return 'OFFICE';
  return ext || 'BIN';
}
