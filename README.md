# fwrra — Firewall Rule Risk Analyzer

A single-file, browser-based tool that parses a firewall configuration and
scores every enforced rule for exposure risk — the kind of triage view
vendor management consoles don't give you in one place. It runs entirely
client-side: nothing you load is uploaded anywhere.

**Current vendor support: Cisco ASA, Fortinet FortiGate (FortiOS), and
Palo Alto (PAN-OS).** Drop a config from any supported vendor onto the
combined build and it auto-detects which parser to use — see
[Multi-vendor architecture](#multi-vendor-architecture) below for how the
codebase is laid out.

## What it does

- Parses vendor-specific rule/object syntax down to a common model: every
  rule's source, destination, and service resolved to its actual members
  — click a rule to expand groups/objects recursively.
- Scores each **enforced** rule 0–100 based on exposure (how broad the
  source/destination scope is) and service risk (whether the port/protocol
  is a common file-transfer or lateral-movement vector — FTP, SSH, SMB,
  RDP, etc.), then combines them into one risk score with a plain-English
  breakdown of how it got there.
- Flags rules with no logging, and flags silent `deny` rules more strongly,
  since those are the ones that hide reconnaissance and attack traffic.
- Detects and flags default-allow behavior that isn't expressed as an
  explicit rule (for ASA: implicit permit any/any between a higher- and
  lower-security interface with no inbound ACL applied) — easy to miss in
  a manual config review.
- Sorts, in its default view, most-trusted zone/interface to least-trusted
  (e.g. inside→outside first, outside→inside last), with each rule
  numbered by its position in its own rule list. You can sort by any
  column and jump back to this default order with one click.

- A **Risk analysis** switch (top right) hides every score, band, policy
  verdict and score-based filter/column — useful for clean audit screenshots of
  the rules. The CSV export drops its score columns too.
- For Cisco ASA, a **Remote-access VPN** tab enumerates AnyConnect access:
  address pools, tunnel-groups, group-policies, per-user overrides, each
  group's vpn-filter ACL (scored), and whether split tunneling is Enabled or
  Disabled — with where each value is inherited from. It is grouped by
  group-policy: one collapsible block per policy (`+` / `-`, plus Expand all /
  Collapse all) so each policy can be evaluated on its own. It has its own CSV
  export (the header Export CSV button follows the active tab).

## What it doesn't do

- **NAT is out of scope.** This is a rule risk-analysis tool, not a NAT or
  full network visualizer. NAT/translation configuration is ignored for
  every vendor.
- It doesn't verify the config is syntactically complete or fully valid —
  it's a best-effort parser aimed at real-world exported/running
  configuration, not a compiler.
- Risk scores are a heuristic triage aid, not a compliance verdict. Treat
  a high score as "look at this first," not "this is definitely wrong."

## How it reads your config (Cisco ASA)

Paste in the **whole configuration** (a full `show running-config` or
saved config file) rather than just the ACL section. The tool needs the
rest of the config to give you an accurate picture:

- **Interfaces**: `nameif` and `security-level` on every `interface`
  block, used to order rules and to detect the ASA's implicit
  higher→lower permit behavior.
- **Access-groups**: `access-group <acl> in|out interface <name>` is what
  tells the tool an ACL is actually enforced. An ACL defined but never
  bound to an interface has no effect on traffic, so rules belonging to
  it are excluded from the results entirely — only rules from ACLs that
  are actually applied are scored and shown.
- **Objects and object-groups**: referenced by name in ACL entries, and
  resolved recursively so nested groups expand fully in the UI.
- **Logging**: the `log`, `log <level>`, and `log disable` keywords on
  each ACE, used to populate the Logging column.
- **NAT is ignored.** `nat`, `global`, and `static` lines are not parsed
  and have no effect on scoring.

## How it reads your config (Fortinet FortiOS)

Paste in the **whole configuration** (a full `show` or a config backup —
the `#config-version=FGT...` header is how the tool recognizes it). As with
ASA, it needs the surrounding config, not just the policy table:

- **Interfaces and routing**: every `config system interface` block (name,
  `set role`, IP) plus `config router static`. FortiGate has no numeric
  security-level, so the tool infers trust for rule ordering from routing:
  the interface that egresses a **default route** (a static route with no
  `set dst`, i.e. `0.0.0.0/0` — the gateway can be dynamic/DHCP with no IP)
  is treated as the internet edge / least trusted, then `set role`
  (wan/dmz/lan) fills in the rest.
- **Policies**: every `config firewall policy`. FortiGate default-denies,
  so — unlike ASA — there's no implicit-permit to synthesize; only explicit
  policies are scored. A policy with `set status disable` is tagged
  inactive (hidden by default, toggleable), not dropped, and keeps its
  FortiGate policy ID.
- **Addresses and services**: `firewall address`/`addrgrp` and
  `firewall service custom`/`group`, resolved recursively (a policy's
  multi-member `srcaddr`/`dstaddr` list is treated as an intentional group;
  `all` means any).
- **Logging**: `set logtraffic all | utm | disable` (or absent) populates
  the Logging column, with the same flagging as ASA.
- **NAT is ignored.** `set nat enable`, VIPs, and IP pools are not parsed
  and have no effect on scoring.

The general shape is the same for every vendor (whole config in, NAT
ignored, zone/interface + rule-application + object + logging all
evaluated); PAN-OS will get its own version of this section when its parser
lands.

## Using it

Open `dist/fwrra.html` (or a per-vendor build like `dist/fwrra-asa.html`)
in any modern browser (Chrome, Firefox, Edge, Safari). No server, no
install, no internet connection required after the page loads — it's one
HTML file with everything embedded.

1. Drop your config file onto the page, or click to browse for it.
2. Rules are scored and listed, most-trusted zone/interface first by
   default.
3. Click any rule to expand it: resolved group membership, service/port
   breakdown, and the exact risk-score calculation.
4. Use the filters and "Show inactive" toggle to narrow the view; sort by
   any column; export the current view to CSV.

## Building from source

The distributable HTML files are generated from the modular source in
`/source`. You don't need to build anything to use the tool — `dist/`
already contains built files — but if you want to modify the tool:

```
node build.js                # builds dist/fwrra.html (all wired-in vendors)
                              # plus dist/fwrra-<vendor>.html per vendor
node build.js --vendor=asa   # builds just dist/fwrra-asa.html
```

No dependencies, no bundler — `build.js` uses only Node's built-in
`fs`/`path` modules, so any reasonably recent Node.js (14+) will run it.

## Multi-vendor architecture

```
source/
  shared/           # vendor-neutral: risk scoring math, syslog severity
                     # naming, and the vendor registry/auto-detect. Every
                     # vendor's resolve.js uses these.
  vendors/
    asa/            # Cisco ASA: parser.js + resolve.js
    fortios/        # Fortinet FortiGate: parser.js + resolve.js
    panos/          # Palo Alto PAN-OS: parser.js + resolve.js
  ui.js             # vendor-neutral presentation layer
  template.html     # page shell, styles, DOM structure
```

Adding a vendor means writing a `parser.js` (raw config text → a
vendor-shaped intermediate representation) and a `resolve.js`
(intermediate representation → the scored, UI-ready rule list) for that
vendor, registering it with `registerVendor({ id, label, detect, parse,
buildRuleset })` at the bottom of its `resolve.js`, then adding its name to
`build.js`'s `VENDORS` array. `ui.js` and `shared/` don't need to change —
`ui.js` auto-detects the vendor from the dropped config and consumes the
scored-rule shape as a black box. See `CLAUDE.md` for the exact contract
`resolve.js` needs to satisfy and the design decisions baked into the
existing implementations that new vendors should stay consistent with (or
deliberately diverge from, if a vendor's model genuinely calls for it).

## Disclaimer

This is a triage aid built to speed up manual config review, not a
certified security-audit tool. Verify anything it flags before acting on
it, and don't rely on it as your only control for firewall rule review.
