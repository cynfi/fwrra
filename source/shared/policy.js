// ============================================================
// Policy standard (deny-by-default) + verdict engine (DESIGN.md §5-6)
// ============================================================
// A declarative, user-editable standard: a list of prohibited traffic patterns
// keyed on rule DIRECTION (ingress/egress/internal, from the direction model)
// and SERVICE (well-known port groups). The verdict is a governance GATE,
// independent of the graduated risk score — a rule can be low-scoring yet
// against policy (e.g. inbound NetBIOS from the internet). This engine is
// vendor-neutral and DOM-free so it is portable into a separate firewall-rule-
// request / change-control tool, where each proposed rule is evaluated the same
// way an existing rule is in audit.
//
// A verdict of `against-policy` is NOT an auto-reject: it is a finding that
// triggers either remediation or a documented, time-bound exception (risk
// acceptance). The exception store itself is app-specific (ui.js keeps one in
// localStorage); this engine only decides compliant vs against-policy.

// Named port groups the standards reference (keys are `protocol/port`, matching
// the buyback/service-risk keying). Tunable, like the buyback tiers.
const POLICY_PORT_GROUPS = {
  remoteAccess: ['tcp/22', 'tcp/23', 'tcp/3389', 'tcp/5900', 'tcp/512', 'tcp/445', 'tcp/139'],
  fileTransfer: ['tcp/445', 'tcp/139', 'tcp/21', 'tcp/20', 'udp/69'],
  snmp: ['udp/161', 'udp/162'],
  dataStores: ['tcp/1433', 'tcp/3306', 'tcp/5432', 'tcp/6379', 'tcp/27017', 'tcp/9200', 'tcp/9300', 'tcp/6443', 'tcp/10250', 'tcp/2375'],
  backdoor: ['tcp/12345', 'tcp/12346', 'tcp/1', 'udp/1', 'tcp/7', 'udp/7', 'tcp/9', 'udp/9', 'tcp/11', 'tcp/13', 'udp/13', 'tcp/15', 'tcp/19', 'udp/19', 'tcp/79', 'tcp/60001'],
};

// Shipped defaults. `direction`: 'ingress' | 'egress' | 'internal' | 'any'.
// `services`: array of `protocol/port` keys, or the literal 'any' (matches a
// permit that allows any port). Org-editable; this is a starting point.
// `services: 'any'` matches an unrestricted (any-port) permit — the single
// "unrestricted access" finding for a broad rule. Port-specific entries match a
// rule that EXPLICITLY names a prohibited port (the smoking-gun case) and do NOT
// also fire on any-port rules — otherwise every broad rule would match every
// port group at once. The any-service entries (FW-STD-02 ingress, FW-STD-07
// egress) already capture that a broad rule includes the prohibited ports.
const DEFAULT_POLICY_STANDARD = [
  { id: 'FW-STD-01', direction: 'ingress', services: POLICY_PORT_GROUPS.remoteAccess,
    rationale: 'Remote-access / file-share ports must not be reachable from untrusted (internet) sources.' },
  { id: 'FW-STD-02', direction: 'ingress', services: 'any',
    rationale: 'No unrestricted (any-service) inbound access from the internet — this implicitly exposes every high-risk port.' },
  { id: 'FW-STD-03', direction: 'ingress', services: POLICY_PORT_GROUPS.snmp,
    rationale: 'SNMP must not be reachable from the internet (info disclosure / device reconfiguration with weak community strings).' },
  { id: 'FW-STD-04', direction: 'ingress', services: POLICY_PORT_GROUPS.dataStores,
    rationale: 'Databases / infrastructure control planes must not be exposed inbound from the internet.' },
  { id: 'FW-STD-05', direction: 'any', services: POLICY_PORT_GROUPS.backdoor,
    rationale: 'Backdoor / no-legitimate-use ports must not be explicitly permitted in any direction.' },
  { id: 'FW-STD-06', direction: 'egress', services: POLICY_PORT_GROUPS.fileTransfer,
    rationale: 'High-risk file-transfer ports outbound to the internet are an exfiltration path and require an exception.' },
  { id: 'FW-STD-07', direction: 'egress', services: 'any',
    rationale: 'Unrestricted (any-service) outbound to the internet should be narrowed to required ports — it implicitly permits high-risk exfil and backdoor ports.' },
];

// Does a permit rule EXPLICITLY name this protocol/port? (Any-port permits are
// handled by the dedicated `services: 'any'` standards, not here.)
function ruleExplicitlyPermitsPort(rule, key) {
  return (rule.services || []).some(c => buybackKeyForCombo(c) === key);
}

function policyDirectionMatches(entryDir, ruleDir) {
  return entryDir === 'any' || entryDir === ruleDir;
}

// Evaluate a rule against the standard. `rule` needs { action, direction,
// services (resolved combos), isAnyPort }. Only permits can violate; denies
// (which enforce policy) are compliant. Returns { verdict, matches:[{id,
// rationale}] } where verdict is 'compliant' | 'against-policy'.
function evaluatePolicy(rule, standard) {
  standard = standard || DEFAULT_POLICY_STANDARD;
  if (rule.action !== 'permit') return { verdict: 'compliant', matches: [] };
  const matches = [];
  for (const e of standard) {
    if (!policyDirectionMatches(e.direction, rule.direction)) continue;
    let hit;
    if (e.services === 'any') hit = !!rule.isAnyPort;
    else hit = !rule.isAnyPort && e.services.some(k => ruleExplicitlyPermitsPort(rule, k));
    if (hit) matches.push({ id: e.id, rationale: e.rationale });
  }
  return { verdict: matches.length ? 'against-policy' : 'compliant', matches };
}
