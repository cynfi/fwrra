# fwrra — Scoring & Policy Model (design blueprint)

**Status: agreed design, not yet fully implemented.** This document is the
blueprint for the next major evolution of the risk engine, deliberated with
the user across several rounds. It supersedes some earlier decisions recorded
in `CLAUDE.md` (noted inline where it does). Implement against this; when a
piece lands, fold the "how it actually works" details back into `CLAUDE.md`'s
design-decisions section and mark the item done here.

This model is intended to be **portable**. The scoring + policy engine is meant
to live not only in fwrra (the read-only analyzer) but also inside a separate
**firewall-rule-request / change-control tool**, where each requested rule is
risk-assessed on its own before approval. So the engine must stay a
self-contained, vendor-neutral, DOM-free module in `source/shared/` — no
dependency on fwrra's UI. fwrra and the request tool are two front-ends over
the same engine.

---

## 1. Two outputs per rule, not one

Every rule (existing rule in an audit, or a proposed rule in a request)
produces **two independent results**:

1. **A graduated risk score (0–100)** — the inherent risk math, for triage and
   as the evidence base for change-control decisions. Two flavors:
   - **inherent** — the rule scored in isolation (all a request needs on its
     own; the conservative worst case).
   - **in-context** — inherent minus *buyback credit* earned from compensating
     controls already present in the target rulebase (§4). Requires the
     rulebase as context; only available in audit mode or when a request is
     evaluated against a live config.
2. **A policy verdict** — a compliance state against a declarative standard
   (§5): `Compliant` / `Against policy — open` / `Against policy — exception
   accepted`. This is a governance gate, **not** derived from the number. A
   request can be low-scoring yet against policy (e.g. inbound NetBIOS from the
   internet), and vice-versa.

The score prioritizes; the verdict gates. Neither replaces the other.

---

## 2. Firewall role toggle (internet-facing vs internal)

A user-set **firewall role**, auto-defaulted from detection and overridable:

- **Internet-facing** — auto-selected when a default route egresses an edge
  interface (see §3). A broad/`any` **destination on an outbound rule is the
  expected baseline** (letting internal users reach the internet is the box's
  job) and is not penalized on destination breadth alone. The real outbound
  risk is *which ports* may leave (exfil/C2) and *which sources*.
- **Internal segmentation** — no default route to an edge. Here data is not
  supposed to leave a zone, so broad/`any` outbound **is** penalized, and
  high-risk transfer ports (SMB, etc.) crossing a zone boundary are a direct
  policy concern regardless of direction.

The role changes exposure weighting (§3), which ports are "expected," and what
the policy standard prohibits (§5).

---

## 3. Direction-aware exposure

**This reverses the earlier decision (recorded in `CLAUDE.md`) that interface
direction stays out of the risk model.** That decision produced a real defect:
on an internet-facing firewall every "internal → any" outbound rule scored
~Critical purely from the `any` destination, burying the genuinely dangerous
inbound rules. Direction is now an input to exposure — supplied by each vendor's
`resolve.js` (which knows the interfaces), consumed by a vendor-neutral
`computeExposureScore()` that only sees an enum.

**Zone-trust classes.** Each interface resolves to a trust class from the
existing interface-trust logic:
- `internet` / untrusted — the default-route egress interface (authoritative;
  the gateway may be dynamic/DHCP with no IP, so the egress *device* is the
  signal), or an explicit wan/untrust role.
- `dmz` — role dmz / mid-trust.
- `internal` / trusted — lan/internal, or untagged internal interfaces.

**Direction** of a rule, from its src/dst zone classes:
- **ingress** — source is `internet` (internet → internal). The dangerous
  direction; scored as today (broad/untrusted *source* is the threat; `any→host`
  high, `any→any` critical).
- **egress** — destination is `internet` (internal → internet). A broad/`any`
  destination is the expected baseline and is **not** penalized, but a **narrow
  destination is credited** (egress restricted to named resolvers/partners is
  genuine least-privilege). Exposure = `srcBreadth × w`, where `w` ranges 0.25
  (narrow dst) → 0.5 (any dst), so egress exposure tops out at 50 and the
  **service score dominates** the combined result — for outbound, *what* may
  leave matters more than *how many* hosts may initiate it. Worked feel
  (internet-facing): host → 1 host on HTTPS = Low; subnet → any on expected
  ports (web/DNS) = Medium; subnet → any on ALL ports = High; any → any on ALL
  ports = Critical; egress restricted to 5 named DNS servers = Medium (vs any→any
  DNS = High). The any-port bump is skipped for egress (service already carries
  it).
- **internal** — neither side is internet; today's symmetric src/dst blend.

**Expected ports** (internet-facing egress): http/80, https/443, tcp+udp/53,
ICMP **echo-request** (ping). These already carry low service-risk scores, so
direction-aware egress scoring naturally lands "internal → any on expected
ports" at Low without a special-case list. Note echo-request is expected
(benign); generic non-echo ICMP is not (C2 tunneling), and blocking echo-request
earns **no** hardening credit (§4) because it isn't a security control.

`deny` is still always 0; `any↔any` is still 100.

---

## 4. Buyback / hardening credit (compensating controls)

Broad permits are less risky when the rulebase first **carves the dangerous
slices out of them**. The buyback credits that, per-rule, via matching.

### 4.1 Matching (src / dst / protocol-port)

For a broad permit `P` (e.g. `dst=any` and/or `service=any`), a preceding
**enabled, broad** deny `D` earns credit against `P` when `D` carves a
high-risk slice out of `P`'s scope on any axis:
- **destination/source** (geo case): `P dst=any`, `D dst=China/Russia/NK` (a
  strict subset of any) with overlapping source → credit.
- **protocol/port** (port case): `P service=any`, `D service=SMB` with
  overlapping src/dst → credit for SMB.
- **geofence / negated allow-list case**: `D` denies everything EXCEPT an
  allow-list (a *negated* source/destination — PAN-OS `negate-source` /
  `negate-destination`), i.e. "deny all sources that are NOT the friendly
  countries." A later permit that is **broad on that same axis** (e.g.
  `P src=any`) is credited, because the hostile majority of that axis was
  already denied first. This is the negated analogue of the geo case (the deny
  names the *good* set and negates, instead of naming the *bad* set). Credit is
  moderate and capped (`BUYBACK_GEOFENCE_PER`≈8, cap 16). Note the value here is
  *threat* reduction, not address-space reduction — "US + friendly" is still a
  huge slice of IPv4 — so it is a fixed compensating-control credit, and (per
  §4.3) it **respects the exposure floor** like every other buyback: a
  geofenced `any`-source leftover permit therefore keeps its exposure score, and
  the credit is surfaced in the breakdown without piercing exposure.

`D` must be on the same egress path (srcintf/dstintf overlapping `P`) and
enabled. (The geofence case keys off the negated axis and the permit being broad
on it, independent of the destination-cover check the port case needs.)

**Shadow analysis is explicitly OUT OF SCOPE.** We credit that a matching block
*exists and applies*; we do **not** verify it isn't shadowed by an earlier
broader permit (rule-order effectiveness). That is the domain of dedicated
policy-analysis tools (Tufin, AlgoSec, FireMon). The output must state this
limitation plainly: *"credit reflects that the block exists and matches; it does
not verify rule-order effectiveness."*

### 4.2 Credit weights (three tiers)

Weights are **not** the raw `SERVICE_RISK_TABLE` scores — they measure the
*real-world value of blocking the port at an edge*, which discounts obsolete
ports whose inherent score overstates their present relevance (e.g. finger).
Tunable list, like the subnet-penalty set.

| Tier | Ports | Credit each |
|------|-------|-------------|
| 1 | SMB **5**, Docker-API-noTLS **4**, NetBus **4**, FTP **4**, SSH **3**, RDP **3**, TFTP **3**, telnet **2** | as shown |
| 2 | NetBIOS, rexec, MS-SQL, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, k8s-API, kubelet, VNC, SNMP, ICMP-except-echo | **1** each |
| 3 | obsolete/recon: tcpmux, echo, discard, systat, daytime, netstat, chargen, finger, bootp, xdmcp, lpr, talk/ntalk, uucp, cisco-aux, UPnP/SSDP | **0.25** each |

Rules: echo-request (ping) = **0** (expected, not a control). SNMP sits at
tier-2 for buyback weight but is a *policy-prohibited* pattern inbound on a
border firewall (§5) — its danger is direction-dependent, not weight-dependent.
Decimals only appear in the tier-3 intermediate sum; **round the tier-3 subtotal
up to the next integer**, and the final score is always an integer.

### 4.3 Applying credit to a rule

The earned credit **reduces the individual broad rule's score** toward the floor
it would have if those high-risk ports/destinations were actually removed from
its scope — i.e. buying back every high-risk port from a `service=any` outbound
rule pulls its service-risk component down toward "only benign ports remain."
The per-rule inherent score is unchanged; the in-context score reflects the
buyback. Example a reviewer would see: *"85 standalone, 40 in-context — SMB/RDP/
etc. already blocked outbound."*

---

## 5. Policy standard (deny-by-default) & verdict

An org's written policy, expressed as a **user-editable declarative ruleset
shipped with sensible defaults** (policy-as-code — policies genuinely vary by
org). Each entry is a prohibited pattern keyed on zone-trust *classes* (not
literal interface names), roughly:

```
{ id: "FW-STD-01", direction: inbound, srcClass: internet, dstClass: any,
  service: [NetBIOS, SMB, telnet, SSH, RDP, rexec, backdoor-ports],
  verdict: prohibited,
  rationale: "Remote-access / file-share / backdoor ports from untrusted sources." }
```

Shipped defaults (illustrative): no inbound NetBIOS/SMB/telnet/SSH/RDP from
internet; no inbound `any→any`; no inbound SNMP on a border firewall; no
backdoor ports in any direction; high-risk exfil ports outbound flagged.

**One definition drives both jobs** — the prohibited-port list, the buyback
priority list, and the request-rejection list are the *same list* seen from
three angles: "you must block this" ⇄ "you get credit for blocking this" ⇄
"requesting this needs an exception."

1. **Request desk** — match a proposed rule against the standard. A match on a
   `prohibited` pattern → verdict `Against policy — open`, routed to *risk
   assessment + documented exception* (NOT auto-rejected — see §6). In-policy
   requests flow by risk score.
2. **Audit** — for each standard, check whether the live config enforces it
   (explicit block, or covered by default-deny). Enforced → buyback credit.
   Not enforced, or contradicted by a permit → a compliance-gap finding.

---

## 6. Verdict states & the exception workflow

`Against policy` is a **finding that triggers action**, never a dead-end. Real
firewalls carry justified exceptions; the model makes them explicit and owned.

- **Compliant** — no conflict.
- **Against policy — open** — conflicts, no justification on file. Default
  expectation is *remediate* (change/remove the rule). A legitimate production
  need instead kicks off a **risk assessment**.
- **Against policy — exception accepted** — conflicts, but an approved risk
  acceptance is attached. Rule stays, tracked.

**An exception is first-class, auditable data:**
- justification (the production use),
- risk acceptor / owner (who signed off),
- date + **expiry** (time-bound, not forever),
- compensating controls referenced (e.g. source restricted to one /32, jump
  host + MFA, logging on),
- link to the **risk assessment** that justified it.

The **risk score + buyback are the risk-assessment evidence**: a high inherent
score partially bought back by existing blocks and tight scope is a defensible
exception; a high score wide open with no compensating controls is not.

**Audit consequences:** an against-policy rule with no exception = an *open
finding* ("must change"). With a valid exception = tracked risk (not an open
finding) but still surfaced, and **re-surfaced at expiry / periodic review** —
an expired exception flips back to open, so exceptions never silently become
permanent.

---

## 7. Multi-vendor applicability

The engine is vendor-neutral; each vendor's `resolve.js` supplies only: the
resolved endpoints/services (existing contract), plus **zone-trust class** and
**direction** per rule. The novelty (direction exposure, buyback, matching,
policy verdict, exceptions) is built once in `shared/`.

| Concept | Cisco ASA | Fortinet FortiOS | Palo Alto PAN-OS | Cisco Firepower (FTD/FMC) — planned |
|---|---|---|---|---|
| Trust source | native security-level (0–100) | default-route egress + `set role` | zone (untrust/trust/dmz) + default-route egress | security zones + default-route egress (like PAN-OS) |
| Default behavior | permit high→low (implicit rules synthesized) | default-deny (no synthesis) | default-deny interzone / allow intrazone (no synthesis) | ordered ACP + explicit **Default Action** (Block/Allow) at the end; no synthesis |
| Rule identity | ACL name + ACE seq | policy ID | rule name | ACP rule name + position |
| Disabled marker | `inactive` | `set status disable` | `disabled yes` | rule `Enabled: false` |
| Service identity | protocol/port | protocol/port | **App-ID and/or service** — App-ID mapped to port(s) | port objects **and/or** application conditions — apps mapped to port(s), like PAN-OS |
| Config format | line grammar | config/edit/set/next/end | **"set" format first**; XML export later | **`show access-control-config` text** first; FMC REST JSON later |
| Actions | permit / deny | accept / deny | allow / deny | **Allow / Trust / Monitor / Block / Block-with-reset / Interactive-Block** (see §10) |

**PAN-OS notes for whoever implements it:**
- Shares FortiOS's **default-route → internet-edge** detection and
  **default-deny** model — the zone-trust/direction machinery is directly
  reusable; no core rework.
- **App-ID is the one real wrinkle.** A security rule may permit
  `application ssh` rather than `service tcp/22`. The buyback/matching engine
  (§4) must key on a normalized `{protocol, port}` identity that a vendor can
  derive from *either* a port *or* an App-ID mapped to ports. Design the
  matcher that way now (see §8) so PAN-OS is additive-only; ship a common
  App-ID→port map (ssh→22, ms-ds-smb→445, rdp→3389, …) with an
  `application any` fallback to "any port."
- Parse **set format** first (`set rulebase security rules <name> from <zone>
  to <zone> source … destination … application … service … action allow|deny`);
  XML `running-config` export support **[DONE]** — `parsePanOSConfig()` sniffs
  the format and routes XML through a DOMParser-based path that yields the same
  `config` shape (pbf/nat rulebases skipped, NAT still out of scope).

---

## 8. Implementation phasing

The vendor-neutral machinery carries all the novelty and risk, so build and
stabilize it on the two existing vendors first, then add PAN-OS as an
additive step against the now-stable contract.

- **Phase 1 — shared model + ASA/FortiOS.**
  1. Zone-trust classes + per-rule direction, supplied by ASA & FortiOS
     `resolve.js`; consumed by a direction-aware `computeExposureScore()`.
  2. Firewall-role toggle (auto-default + override) in `ui.js`.
  3. Buyback engine: tiered credit table, src/dst/port matcher (no shadow
     analysis), inherent-vs-in-context scoring. Key the matcher on a
     normalized `{protocol, port}` service identity **from the start** so
     App-ID slots in later with no rework.
  4. Policy-standard engine: declarative ruleset + defaults, verdict
     computation, exception data model, audit-gap + hardening surfaces in
     `ui.js`.
- **Phase 2 — PAN-OS. [DONE]** `vendors/panos/` parser (set format, one
  attribute per line, plus the XML `running-config` export parsed via the
  platform DOMParser into the same shape) + resolve supplying the same zone-trust/direction/
  service-identity contract, with a `PANOS_APPID_PORTS` map so
  `application-default` rules score on their App-ID's real ports (e.g.
  `application ms-rdp` → tcp/3389, correctly triggering the remote-access-
  inbound standard). Landed with **zero `shared/` changes** — the rule-of-three
  validated the abstraction.

- **Phase 3 — Cisco Firepower (FTD/FMC). [PLANNED — blocked on a sample]** New
  `vendors/firepower/` parser + resolve for the Access Control Policy (see §10).
  Expected to reuse the shared engine like PAN-OS did (zone-trust, direction,
  buyback, policy verdict); the new work is the ACP text parser and the
  action-verb mapping. **Not startable without a real `show access-control-config`
  (or FMC JSON) sample** — the exact text layout varies by version and must be
  built against a real artifact, exactly as ASA/FortiOS were.

**Economy captured by designing for three now:** the contract additions
(zone-trust, direction, normalized service identity) are specified with PAN-OS's
zone model and App-ID constraint already in view, so Phase 2 needs no core
redesign. **Economy deliberately declined:** writing the PAN-OS set-format
parser *simultaneously* with the core-model changes — that triples the in-flight
churn while the contract is still moving. Build core on two, add the third once
it's stable.

---

## 9. Open tunables (expect user input)

- The **buyback tier lists** (§4.2) — like the subnet-penalty set, these are
  calibrated with the user, not fixed.
- The **policy standard defaults** (§5) — shipped defaults are a starting point;
  the standard is user-editable.
- The **App-ID → port map** (§7) — common mappings shipped; extendable.

---

## 10. Cisco Firepower (FTD/FMC) — planned vendor

**Firepower is NOT an ASA variant.** FTD runs an ASA-like data plane (LINA) for
interfaces / NAT / routing, but its rules live in an FMC-managed, ordered
**Access Control Policy (ACP)** — zone-based and application-aware, far closer to
PAN-OS/FortiOS than to ASA's `access-list` grammar. Do **not** try to extend the
ASA parser for it; it is its own `vendors/firepower/` vendor.

### Config artifact (in priority order)

- **`show access-control-config`** (FTD CLI) — a text dump of the *deployed* ACP,
  one block per rule (`Action:`, `Source Zones:`, `Destination Zones:`, `Source
  Networks:`, `Destination Networks:`, `Destination Ports:`, `Applications:`,
  `Logging Configuration:`, …). **This is the first parse target** — it is a file
  a user can hand the tool, analogous to a FortiOS/PAN-OS export.
- **FMC REST API** (policy as JSON) — cleanest structurally, but an API pull, not
  a dropped file; a later option.
- **Do NOT parse FTD `show running-config`** for rules — that is the LINA config
  (interfaces/NAT/routing, ASA-ish syntax) and does **not** contain the real ACP.
  It could still be a secondary source for zone↔interface and default-route
  detection if provided alongside.

### Action-verb mapping (the real new work)

Firepower has more than allow/deny, and two verbs need care:

| ACP action | Maps to | Note |
|---|---|---|
| **Allow** | `permit` | normal inspected allow |
| **Trust** | `permit` | allowed **without** Snort inspection — arguably *higher* risk than Allow (bypasses IPS/file policy); flag it (e.g. a small service-risk bump or a policy-standard entry "Trust to/from untrusted"). |
| **Block**, **Block with reset** | `deny` | drop |
| **Interactive Block** (± reset) | `deny` | user can click through, but model as deny for scoring |
| **Monitor** | *neither* | a Monitor rule only **logs** and does not terminate the match — evaluation continues to later rules. It must **not** be scored as a permit or a deny, and it must **not** earn buyback credit or a policy verdict. Surface it as an informational row. This is the one genuinely new control-flow concept vs the other vendors. |

### What reuses vs what's new

- **Reuses** (no `shared/` changes expected): zone-trust (security zones +
  default-route egress, like PAN-OS), direction, exposure, buyback, policy
  verdict, exceptions. Applications map to `{protocol, port}` via the same
  approach as `PANOS_APPID_PORTS`.
- **New**: the ACP text parser; the action-verb mapping above (esp. Trust risk
  and Monitor's pass-through semantics); optionally the **Prefilter policy**
  (fastpath / block / analyze rules evaluated *before* the ACP) — treat as a
  later enhancement, note it but don't block v1 on it.

### Blocked on

A real `show access-control-config` (or FMC JSON) sample. Build and validate
against the actual artifact, exactly as ASA/FortiOS/PAN-OS were — the text layout
varies by FTD/FMC version, so guessing the format would be fragile.
