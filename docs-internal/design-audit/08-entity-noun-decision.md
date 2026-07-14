# trstctl — Entity-noun consolidation spike (C-N1)

**Card:** C-N1 in `07-closeout-sprint-plan.md`. **Scope:** decision doc only — no rename, no route change, no nav change this train.
**Question:** Should Identities / Workloads / Agents / Owners remain four nouns, and if not, what replaces them and what does it cost?
**Evidence base:** `realGuiSurfaces` metadata (`web/src/lib/navigation.ts`), the generated `Identity.kind` enum, the Fleet module (live since S-B2), and the DA-06/DA-07 findings (04-ia-proposal §17, §99).

---

## 1. Inventory — what each noun's surface actually operates on

Walked from `realGuiSurfaces` (featureId → component → routes → evidence), post-C-A1 route state:

| Noun (route) | Features | Component | What it really is (evidence strings) |
|---|---|---|---|
| **Identities** `/identities` | F4 (issue/deploy/revoke transitions + request intake), F6 (manual lifecycle transitions), F47 (revoke + audit trail), F59 (NHI lifecycle rows and owner link) | `Identities` | **The lifecycle ledger.** Every credentialed thing has a row here; the verbs are state transitions (issue → deploy → renew → revoke). |
| **Workloads** `/workloads` | F25 (dynamic/ephemeral credential issuance, leases, TTL), F30 (attestation policies: TPM/AWS/GCP/Azure/K8s/GitHub, SVID issuance), F61 (AI-agent broker issuance) | `Workloads` | **The attestation & dynamic-issuance console.** The verbs are attest, broker, lease — *how software proves itself and gets short-lived credentials*. |
| **Agents** `/agents` | F3 (agent fleet + enrollment tokens), F54 (bootstrap token install, renewal evidence, endpoint discovery) | `Agents` | **The installed-software fleet.** The verbs are enroll, bootstrap, renew — *trstctl's own daemons on customer machines*. |
| **Owners** `/owners` | F59 (**shared with Identities**: "NHI lifecycle rows and owner link") | `Identities` (shared) | **The accountability plane.** Humans/teams answerable for NHIs. Not a credential holder at all — a governance edge. |

Two structural facts fall out of the metadata itself:

1. **Owners is already not a peer.** It shares F59 *and its component* with Identities — the console's own config says Owners is a lens on the identity ledger, not a fourth entity type.
2. **The type system has one noun with kinds.** `Identity.kind` = `x509_certificate | ssh_certificate | ssh_key | secret | api_key | workload_identity` (`api-types.gen.ts:1807`). `workload_identity` is a *kind of identity* — the API never had four nouns.

## 2. Overlap evidence

- **DA-06/DA-07 (04 §17):** the noun pairs are "disambiguated only by prose inside page descriptions" — live-confirmed drift class, partially fixed by S-A2's naming parity but the *conceptual* overlap remains: a CI runner plausibly lives under Identities (it has credentials), Workloads (it attests), or Agents (it runs a daemon).
- **The Fleet module already merged two of them in practice.** S-B1/S-B2 put `/agents` + `/workloads` in one module band (`navModules.fleet`, F3/F25/F30/F54/F61) and users have navigated them as one product since. The rail merge is *de facto* shipped; only the nouns and routes are unmerged.
- **Dashboard treats them as one population:** the NHI inventory panel counts by `kind` over one list; "Agents online" is `inventoryCount(…, "agent")` — a kind filter, not a separate store.
- **What does NOT overlap:** Agents-the-daemons (enrollment tokens, install commands) are operationally distinct from Workloads-the-attestors. The evidence strings share no verbs. The overlap is *naming*, not function.

## 3. Options, with costs

**Option 1 — Keep four nouns, add one-line disambiguators.**
Nav/H1/docs unchanged; each page description gets a "not to be confused with…" line (already partially true). Cost: ~0. Risk: the DA-06 confusion class stays; every new user still pays the taxonomy tax. *This is the do-nothing baseline, and it is defensible now that naming parity (S-A2) and the Fleet band (S-B2) absorbed the worst of it.*

**Option 2 — Fold Agents + Workloads into one "Fleet" surface (match the module).**
One route (`/fleet`, tabs = today's two pages), redirects from `/agents` + `/workloads` (C-A1 proved the redirect pattern). Nav: Inventory loses two rows, gains one.
Cost: M. Touches: 2 routes + redirects, `navModules.fleet.routes`, `module_map`/`nav_completeness` fixtures, 5 realGuiSurfaces entries, 2 nav keys → 1 (+es-ES), docs/tour stops naming Agents/Workloads, `Identity.kind` untouched. Risk: `/workloads` is attestation policy administration — burying it a tab deep re-creates the DA-04 "hidden product" smell the A-train just fixed.
Blast radius: web-only; API/CLI unchanged.

**Option 3 — Single "Identities" surface with kind filters; Owners stays.**
`/identities?kind=agent|workload|…` becomes the one inventory; Agents/Workloads become saved views/kind pages; Owners remains the human/team plane.
Cost: L. Every operate-workflow on Workloads (attestation CRUD, broker) and Agents (enrollment) must re-home into kind-scoped panels without violating DESIGN rule 6 (list first); 9 realGuiSurfaces entries, module map (Fleet module would scope *views*, not routes — new concept), docs, tour, es-ES, and the muscle memory of every existing user. Risk: highest; conflicts with 04's decision that Identities is a *global* plane while Fleet is a *module* — merging them makes one surface both global and module-scoped.

## 4. Recommendation

**Option 1 now; Option 2 as the pre-approved follow-up if (and only if) the evidence triggers fire.** Option 3 is rejected outright — it un-ships the global-vs-module boundary 04 chose deliberately.

Rationale: the two changes that hurt users daily (label↔H1 drift, rail scatter) were already fixed by S-A2/S-B2. What remains is a naming redundancy whose fix (Option 2) costs a route migration for a confusion nobody has yet demonstrated *post-B*. The audit's own principle applies: don't move URLs without live evidence.

## 5. Go/no-go checklist for Option 2 (re-verify after ~1 quarter of B-era usage)

Trigger Option 2 if **any two** hold:
- [ ] Support/community questions confusing Agents vs Workloads (or asking "where are my runners?") ≥ 3 in the window.
- [ ] Cmd-K search logs (or tour observations) show users searching "agent" then opening `/workloads` or vice versa.
- [ ] The Fleet module band is the dominant entry path to both pages (nav telemetry / journey completion), i.e. users already treat them as one product.
- [ ] A third fleet-ish noun is about to ship (e.g. device fleets), which would make it five nouns — consolidate before adding.

If triggered, the implementation card is pre-written below. If a full quarter passes with none: close DA-06 as "resolved by S-A2 + S-B2, four nouns intentional," and delete this checklist from the backlog.

## 6. Pre-written card — C-N2 (next train, blocked on §5)

**C-N2 — Fleet surface merge (Agents + Workloads) — M.**
Delivers: `/fleet` route rendering today's two pages as tabs (Agents = fleet & enrollment; Workloads = attestation & dynamic issuance), permanent redirects `/agents → /fleet?tab=agents` and `/workloads → /fleet?tab=attestation`; `navModules.fleet.routes = ["/fleet"]`; Inventory group: two rows → one; realGuiSurfaces F3/F25/F30/F54/F61 → `/fleet`; messages `nav.item.fleet` (+es-ES); docs/tour rename pass; `admin_split.test.tsx`-style redirect guard.
Excludes: any data-model change; `Identity.kind` untouched; Owners untouched.
Tests first: redirect suite; `module_map`/`nav_completeness` updated; naming_parity picks up the new row automatically.
Exit gate: zero broken historical URLs; the Fleet module band and the Fleet route agree; tour stop count unchanged.

---

*Recorded during C-N1, 2026-07-14. The three hardcoded H1s found during research (`Identities.tsx:592`, `Agents.tsx:270`, `Owners.tsx:147`) are C-I2's to fix and do not gate this decision.*
