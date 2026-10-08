# ASA remote-access VPN (AnyConnect) enumeration — design

Status: approved in conversation 2026-10-08; spec awaiting review.

## Goal
For Cisco ASA, enumerate remote-access VPN access for audit evidence: which
address pools exist, which tunnel-groups, group-policies and per-user overrides
use them, and what each VPN identity may reach via its own ACLs. Risk scoring of
VPN filter ACEs must be hideable with the existing "Risk analysis" toggle.

## Non-goals
NAT; DAP (dynamic access policies); certificate maps; IKEv1 site-to-site
tunnel-groups (only `type remote-access` is enumerated); AAA-server-supplied
(RADIUS) attributes, which are not in the config; any change to FortiOS/PAN-OS.

## 1. Parsing (`vendors/asa/parser.js`)
New fields on the returned config: `pools`, `groupPolicies`, `tunnelGroups`,
`users`, `vpnGlobal`. Existing fields are unchanged.

- `ip local pool NAME START-END [mask M]` -> `pools[NAME] = {start,end,mask,count}`.
- `group-policy NAME internal|external` + `group-policy NAME attributes` block ->
  `groupPolicies[NAME]` with: `vpnFilter` (ACL), `splitPolicy`
  (tunnelspecified|excludespecified|tunnelall), `splitAcl`, `addressPools[]`,
  `tunnelProtocols[]`, `dnsServers[]`, `simultaneousLogins`, `rawAttrs` for
  unmodelled lines. `value`/`none` forms handled (`none` = explicit empty, which
  differs from "unset/inherit"). Nested `webvpn` sub-block is skipped.
- `tunnel-group NAME type remote-access`, `... general-attributes`
  (`address-pool`, `default-group-policy`, `authentication-server-group`),
  `... webvpn-attributes` (`group-alias X enable`, `group-url`) ->
  `tunnelGroups[NAME]`. Other tunnel-group types are recorded with
  `type` but flagged non-remote-access and excluded from the view.
- `username NAME attributes` block -> `users[NAME]` with `vpnGroupPolicy`,
  `vpnFilter`, `groupLock`, `framedIp`. Password lines are never stored.
- `access-list NAME standard permit|deny <net> <mask>|host X|any` parsed into the
  same `acls` map (entry `{standard:true, action, src}`; no dst/service). Needed
  for split-tunnel lists. Existing extended parsing untouched.
- Globals into `vpnGlobal`: `sysopt connection permit-vpn`, `webvpn` ->
  `enable <if>`, `anyconnect enable`, `tunnel-group-list enable`.

## 2. Resolution (`vendors/asa/resolve.js`)
New `buildVpnInventory(config, options)` (options carries `firewallRole`).

- Effective attributes follow ASA inheritance: user -> group-policy (the user's
  `vpn-group-policy`, else the tunnel-group's default) -> `DfltGrpPolicy`. Each
  effective value carries `source: 'user'|'group-policy'|'inherited'|'default'`
  so the view can show where it came from.
- Pool resolution order: group-policy `address-pools` overrides tunnel-group
  `address-pool` (ASA behaviour); a user `framedIp` overrides both.
- One **identity row** per tunnel-group, per group-policy referenced by one,
  and per user override. Each shows: pools (with address count), protocols,
  split-tunnel mode + network list, vpn-filter ACL, simultaneous logins.
- **vpn-filter ACEs** are resolved through the existing object/group resolver and
  scored with the existing `scoreEntry(config, entry, direction)`. Direction is
  `'internal'` (symmetric src/dst blend): VPN clients are authenticated and the
  ACL is neither inbound-from-internet nor egress. ACE convention: source =
  remote client, destination = internal. Logging is classified with the existing
  `classifyLogging`. Only ACLs reached through a remote-access identity are
  included, so "only enforced rules are scored" still holds; vpn-filter ACLs
  stay out of the main rule table (they are not `access-group`-bound).
- A group-policy/user with **no vpn-filter** is an explicit finding row ("no
  VPN filter: tunnel user reaches whatever the pool routes to / sysopt
  permit-vpn allows"), not a silent blank. `sysopt connection permit-vpn`
  present is shown as a global finding.
- **Split-tunnel ACLs** are informational: networks tunneled/excluded, expandable,
  never scored. `tunnelall` shown as such.
- Disabled/inactive ACEs are tagged, not dropped (matches the existing rule).
- Findings are factual (config states), not scored, and not gated by the toggle;
  only the per-ACE score/band/breakdown and risk-based filters are.

## 3. Vendor contract extension (`shared/registry.js`, `ui.js`)
Optional vendor hook: `buildInventory(config, options) -> Inventory`.

```
Inventory = { title, sections: [ { id, heading, columns:[{key,label,risk?}],
              rows:[ { cells:{key:value}, detail?: html-safe tree spec,
                       scored?: <same scored shape as rule rows> } ] } ] }
```
`columns[].risk: true` marks score-dependent columns. `ui.js` stays
vendor-neutral: if the registered vendor has `buildInventory`, it renders a tab
("Remote-access VPN"), reusing the existing member-tree and detail renderers
and `escapeHtml()`; otherwise no tab. Scored rows reuse the existing
`riskOn`/`.risk-only` mechanism, so the toggle hides score columns, bands and
calculation sections in this tab too. The role selector triggers a rebuild of
the inventory the same way it rebuilds rules. Document the hook in `CLAUDE.md`.

## 4. UI
Two tabs under the file-info strip when the hook exists: "Rules" (current view)
and "Remote-access VPN". VPN tab sections: Tunnel-groups, Group-policies, User
overrides, Address pools, VPN filter rules, Global findings. Same dark
monospace table style; click-to-expand rows. Search box filters the active tab.
A separate **Export VPN CSV** button (one row per identity and per filter ACE;
score columns omitted when the toggle is off). The existing rule CSV is unchanged.

## 5. Testing
jsdom, as in `CLAUDE.md`, with a sample ASA config covering: two pools; a
tunnel-group with its own group-policy and filter ACL; one inheriting
`DfltGrpPolicy`; a split-tunnel standard ACL (tunnelspecified and
excludespecified); a user override with a different filter; a group-policy with
`vpn-filter none`; a site-to-site tunnel-group (must be excluded);
`sysopt connection permit-vpn`; an inactive ACE. Assert: inheritance sources,
pool counts, filter ACE scores equal `scoreEntry` direct output, toggle hides
all score cells in the VPN tab, VPN CSV columns with the toggle on and off, and
that FortiOS/PAN-OS/combined builds still pass the prior toggle test (no tab on
non-ASA configs). Also confirm the main rule table is unchanged for the ASA
sample.

## 6. Risks / open items
- ASA `vpn-filter` ACEs are evaluated with src/dst reversed for return traffic;
  we document the client->internal convention and do not model the reverse.
- Group-policy attribute grammar varies by ASA version; unmodelled lines are
  kept in `rawAttrs` and shown on expand rather than dropped.
- Real configs with AAA-supplied attributes will under-report; the view states
  that RADIUS/LDAP-supplied attributes are not visible in the config.
