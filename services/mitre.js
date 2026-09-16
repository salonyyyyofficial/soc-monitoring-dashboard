/**
 * mitre.js
 * Minimal MITRE ATT&CK reference covering only the techniques this project
 * uses. Intentionally NOT the full ATT&CK database - per the brief, start
 * small and expand later.
 */
const TECHNIQUES = {
  T1110: {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.',
    url: 'https://attack.mitre.org/techniques/T1110/',
  },
  T1046: {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.',
    url: 'https://attack.mitre.org/techniques/T1046/',
  },
  'T1059.001': {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution, including downloading and running payloads in memory.',
    url: 'https://attack.mitre.org/techniques/T1059/001/',
  },
  T1068: {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may exploit software vulnerabilities or misconfigurations to elevate privileges on a system.',
    url: 'https://attack.mitre.org/techniques/T1068/',
  },
  T1204: {
    id: 'T1204',
    name: 'User Execution',
    tactic: 'Execution',
    description: 'An adversary may rely upon specific actions by a user in order to gain execution, such as opening a malicious file.',
    url: 'https://attack.mitre.org/techniques/T1204/',
  },
};

function getTechnique(id) {
  return TECHNIQUES[id] || null;
}

function listTechniques() {
  return Object.values(TECHNIQUES);
}

module.exports = { getTechnique, listTechniques, TECHNIQUES };
