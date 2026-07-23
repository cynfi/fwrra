# CLAUDE.md

Guidance for Claude (or any assistant) working in this repository.

## What this is

`fwrra` (Firewall Rule Risk Analyzer) is a client-side, multi-vendor
firewall config risk analyzer. One HTML file per build, no backend, no
build dependencies beyond Node's standard library. `source/` holds the
real source of truth; everything in `dist/` is generated — **never
hand-edit `dist/`**, edit `source/` and run `node build.js`.

Cisco ASA is the only vendor implemented today. This document exists
mainly to make adding FortiOS (FortiGate) and PAN-OS (Palo Alto) support
straightforward and consistent with the decisions already made for ASA.

## Repo layout

```
build.js                    # assembles source/ into dist/*.html — no deps.
                             # `node build.js` builds a combined artifact
                             # (all VENDORS) plus one per-vendor artifact.
                             # `node build.js --vendor=<name>` builds just
                             # that vendor.
source/
  template.html              # page shell: <head>, CSS, DOM structure, two
                              # empty <script id="engine-scripts">/<script
                              # id="ui-script"> placeholders build.js fills in
  shared/
    logging.js                # SYSLOG_LEVEL_NAMES — RFC 5424 severity names,
                               # universal across vendors
    risk.js                    # vendor-neutral scoring: SERVICE_RISK_TABLE,
                                # computeExposureScore(), combineRisk(),
                                # riskBand(), classifyEndpointScope(),
                                # maskToPrefixLen(). Pure functions operating
                                # on a normalized {kind, prefixLen} scope
                                # shape and (protocol, port) pairs — nothing
                                # here knows any vendor's config grammar.
  vendors/
    asa/
      parser.js                 # parseASAConfig(text) -> {objects, groups,
                                 # interfaces, acls, accessGroups} — ASA
                                 # config-line grammar only
      resolve.js                 # ASA-specific: resolves objects/groups
                                  # recursively, scoreEntry() (calls into
                                  # shared/risk.js for the actual math),
                                  # classifyLogging() (ASA's log/log
                                  # disable/log <level> grammar), and
                                  # buildRuleset() which assembles the
                                  # final display rows (implicit-permit
                                  # synthesis, default ordering, rule
                                  # numbering)
    fortios/                    # (not yet implemented)
    panos/                      # (not yet implemented)
  ui.js                        # all DOM code: file handling, table
                                # rendering, sort/filter, expand/collapse,
                                # CSV export. Vendor-neutral — consumes
                                # buildRuleset()'s output as a black box
                                # and never inspects vendor-specific fields
                                # directly except through the contract below
dist/
  fwrra.html                  # combined build (all wired-in vendors)
  fwrra-asa.html              # per-vendor build
```

`build.js` loads scripts in this order for any given vendor build:
`shared/logging.js`, `shared/risk.js`, then that vendor's `parser.js`,
then that vendor's `resolve.js`, then `ui.js` last. There's no module
system — everything hangs off the global scope inside the page — so load
order is load-bearing. If a vendor's `resolve.js` needs something from
`shared/`, it must already be defined by the time that vendor's files
load, which the order above guarantees.

## The vendor contract

This is the part that matters most for adding FortiOS/PAN-OS. `ui.js`
never parses vendor syntax and never branches on vendor identity — it
only calls one entry point and renders whatever comes back:

```
buildRuleset(config) -> Array<Row>
```

Every vendor's `resolve.js` must export a `buildRuleset()` (and whatever
internal helpers it needs — `scoreEntry()`, `classifyLogging()`, etc. —
these are implementation details `ui.js` doesn't call directly) that
returns an array of row objects. Two `type`s exist:

- `{ type: 'remark', aclName, text }` — a comment/label, not scored,
  rendered as an inline dim row.
- `{ type: 'rule', id, aclName, ruleNumber, entry, scored, interface,
  direction, implicit, inactive, defaultOrder, implicitNote? }` — a
  scored rule. `ui.js` reads `row.interface`, `row.aclName`,
  `row.ruleNumber`, `row.implicit`, `row.inactive`, and drills into
  `row.scored` for everything risk-related.

`row.scored` (the return value of that vendor's `scoreEntry()`) must have
this shape — this is the actual contract, and it's what `shared/risk.js`
and `ui.js` both depend on:

```
{
  action: 'permit' | 'deny',
  score: number,              // 0-100, final combined score
  band: { label, color },     // from shared riskBand()
  exposure: { score, label },
  service: { score, name, note },
  bonusApplied: boolean,
  services: Array<{ protocol, destPort?, destPortEnd?, isRange? }>,
  srcResolved, dstResolved,   // resolved endpoint trees, see below
  srcScope, dstScope,         // from shared classifyEndpointScope()
  logging: { flagged, severity, label, detail },
}
```

`srcResolved`/`dstResolved` use a small shared vocabulary of `kind`
values that `shared/risk.js`'s `classifyEndpointScope()` and `ui.js`'s
tree-rendering both understand: `any`, `host`, `subnet` (needs
`prefixLen`), `range`, `fqdn`, `literal`, and `group` (needs `members: []`
of the same shape, for recursive rendering). A new vendor's `resolve.js`
must translate its own object model into this vocabulary — don't invent
new `kind` values without updating `classifyEndpointScope()` in
`shared/risk.js` and the tree renderer in `ui.js` to handle them.

`defaultOrder: { level, ifName, ruleNumber }` drives the default sort
(see below) — `level` should be a number where higher = more trusted, on
whatever scale makes sense for that vendor (ASA uses its native 0–100
security-level; a vendor without an explicit numeric trust level will
need to invent a reasonable ordinal, e.g. by zone role).

`row.scored.logging` is produced by that vendor's own `classifyLogging()`
— the ASA one lives in `vendors/asa/resolve.js` and reads ASA's specific
`log`/`log disable`/`log <level>` grammar via `entry.logSetting`. A new
vendor will have different logging syntax (FortiOS: `log-traffic` /
`log-traffic-start`; PAN-OS: log-forwarding-profile attached to a rule)
and needs its own `classifyLogging()` that maps its grammar into the same
`{ flagged, severity, label, detail }` shape, using `SYSLOG_LEVEL_NAMES`
from `shared/logging.js` where a numeric/named severity applies.

## Design decisions worth knowing before you change scoring logic

These were deliberated with the user across several rounds while building
the ASA implementation and aren't arbitrary — check with the user before
changing them silently, and default to keeping new vendors consistent
with them unless a vendor's model genuinely doesn't fit:

- **NAT is explicitly out of scope for every vendor.** This is a
  rule-risk-analysis tool, not a full visualizer. Don't add NAT parsing
  without being asked.
- **Only enforced rules are scored.** For ASA, an ACL not bound via
  `access-group` has no effect on traffic and is excluded entirely (see
  `appliedAcls` in `vendors/asa/resolve.js`). The equivalent concept for
  FortiOS (policy must be in an active policy package / not disabled) and
  PAN-OS (rule must not be disabled, and rulebase/vsys context matters)
  should be enforced the same way — don't score rules that can't
  currently fire.
- **Inactive/disabled rules are parsed and tagged, not deleted.** ASA's
  `... inactive` keyword is tagged on the row (`row.inactive`) and hidden
  by default via a UI toggle, not dropped from the ruleset. Rule
  numbering **includes** inactive rules in the count, matching how the
  vendor's own tooling numbers rules, so numbers don't shift when the
  toggle is flipped. FortiOS (`set status disable`) and PAN-OS
  (`disabled yes`) have their own equivalents and should follow the same
  pattern.
- **Risk score = `max(exposure, service) + 10 if both are elevated
  (≥55), capped at 100`.** This is vendor-neutral, lives in
  `combineRisk()` in `shared/risk.js`, and applies identically regardless
  of which vendor produced the exposure/service inputs. Chosen over pure
  addition or a weighted sum so neither an "any/any on a safe port" nor a
  "narrow host-pair on a risky port" rule dominates unfairly. The
  `ELEVATED_THRESHOLD` (55) and `BOTH_ELEVATED_BONUS` (10) constants are
  tunable but were picked deliberately; don't change them without
  checking in.
- **Exposure scoring anchors** (also vendor-neutral, in
  `computeExposureScore()`): any↔any = 100, deny = 0 always, host↔host
  unidirectional single-port = 20, host↔host any-port
  (bidirectional-equivalent) = 50. Everything else scales between these
  anchors based on prefix length. Subnets with prefix length ≤ 23 are
  treated as "large" and score higher than smaller subnets. A vendor
  whose object model doesn't map cleanly onto host/subnet/any (e.g. FQDN
  objects, dynamic address groups) should resolve down to the closest
  fit in `classifyEndpointScope()`'s vocabulary rather than inventing a
  parallel scoring path.
- **Service risk table (`SERVICE_RISK_TABLE` in `shared/risk.js`)** is
  vendor-neutral (keyed by protocol/port, not vendor syntax) and is a
  starting point covering common file-transfer/lateral-movement vectors
  (FTP, TFTP, SSH, Telnet, SMB, NetBIOS, RDP, VNC, etc.), not exhaustive.
  Every vendor shares this table — don't fork it per vendor. If the user
  asks to add/adjust ports, edit this table directly.
- **Implicit permit-any/any synthesis** is currently ASA-specific logic
  (in `vendors/asa/resolve.js`) modeling the ASA's real default behavior:
  for every interface pair where the source's security level is strictly
  higher than the destination's, if the source has no inbound ACL
  applied, a flagged score-100 "implicit" rule is synthesized. FortiOS
  and PAN-OS both default-deny inter-zone traffic without an explicit
  policy (unlike ASA's default-permit-higher-to-lower), so this specific
  synthesis logic should generally **not** be ported as-is to those
  vendors — but the general idea (flag default behavior that isn't an
  explicit, visible rule) may still apply if either vendor has its own
  default-allow edge cases worth surfacing. Confirm with the user before
  assuming FortiOS/PAN-OS need an equivalent.
- **Default sort order**: most-trusted zone/interface first, ties broken
  by interface/zone name ascending, then by each rule's position within
  its own rule list. Driven by `row.defaultOrder` (vendor-supplied) and
  compared in `ui.js`'s `compareDefaultOrder()`. This is a UI
  convenience, not part of the risk model.
- **Logging classification**: no logging configured, or logging
  explicitly disabled, is flagged; `deny`/block rules without logging are
  flagged at higher severity than `permit`/allow rules without logging,
  since silent denies hide attack/recon traffic. This severity asymmetry
  should carry over to every vendor's `classifyLogging()`.

## Testing

There's no test suite checked into the repo. When changing `source/`
files, the pattern used during ASA development was headless DOM testing
with `jsdom` (not committed as a dependency — install ad hoc if needed):
build the artifact, load it in `jsdom` with `runScripts: 'dangerously'`,
simulate a file drop via a synthetic `File` + `change` event on
`#fileInput`, then assert on the rendered `#ruleTableBody` rows. When
adding a new vendor, write a small representative sample config in that
vendor's syntax (covering: a permit and a deny rule, at least one nested
object-group, an inactive/disabled rule, a rule with and without
logging, and enough interfaces/zones with different trust levels to
exercise default ordering) and run it through this same pattern before
considering the vendor "done."

Before committing changes to shared scoring logic, rebuild
(`node build.js`, with no `--vendor` flag so every vendor's artifact
gets regenerated) and diff the output to confirm the change took effect
in every vendor's build, not just the one you were testing against.

## Style notes

- Vanilla JS throughout, no framework, no build tooling beyond
  `build.js`. Keep it that way — the whole point is a zero-dependency
  file someone can open directly in a browser.
- Dark, monospace-forward UI (CSS variables in `template.html`'s
  `:root`) intentionally modeled on terminal/CLI output — this is a
  tool for engineers reading firewall config data, not a marketing
  surface. Match that register in any UI additions (data-dense tables
  over cards/graphics, mono font for addresses/ports/rule names). Avoid
  vendor-branded colors or iconography in the UI — this tool is
  deliberately vendor-neutral in presentation even though it's
  vendor-aware in parsing.
- HTML escaping: always run user-derived strings (object names, config
  content) through `escapeHtml()` in `ui.js` before interpolating into
  `innerHTML`. The config file is untrusted input, regardless of vendor.
- Keep vendor-specific grammar knowledge inside that vendor's
  `parser.js`/`resolve.js`. If you find yourself wanting to add a
  vendor-name check (`if (vendor === 'fortios')`) inside `ui.js` or
  `shared/`, that's a signal the vendor contract above needs a new field
  instead — raise it with the user rather than special-casing silently.
