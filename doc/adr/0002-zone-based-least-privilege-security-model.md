## ADR-0002: Zone-Based Least-Privilege Security Model

## Status

proposed

---

## Context

We want a robust, least-privilege security posture without sacrificing the ability to manage the database using declarative schema files and automated migrations. Traditional PostgreSQL and Supabase patterns either rely on fragile per-migration grants or aggressive global hardening, both of which tend to drift or break platform tooling over time. We want to make security structural and predictable while retaining schema-driven migration workflows as much as possible.

## Alternatives Considered

Each alternative is evaluated on three axes:

* **Security:** least-privilege strength and resistance to common foot-guns (implicit exposure, search_path risk, function exposure).
* **Declarative Compatibility:** how well the model works with schema-driven diffs and automated migrations without requiring fragile, manual permission bookkeeping.
* **Supabase Compatibility:** likelihood of breaking Supabase-managed roles, Dashboard behavior, platform upgrades, or extension workflows.

### Alternative A: Supabase-Style API Schema With Per-Object Grants (Explicit Permissions)

**Description**
Use Supabase’s API schema pattern, but lock down defaults so that **USAGE and object privileges must be granted explicitly per table, view, function, and sequence** as they are created.

**Security**

* Strong when consistently applied: nothing is exposed until explicitly granted.
* Low tolerance for mistakes: a missed grant breaks functionality; a mistaken grant can expose data or execution.

**Declarative Compatibility**

* Low.
* Declarative diffs generate structure, not permission intent; the grant set becomes a parallel, hand-maintained system.
* High risk of drift as objects are added/renamed and grants lag behind.

**Supabase Compatibility**

* Medium.
* Can work if changes are scoped to application schemas/roles, but tends to create friction with Dashboard-created objects and extension expectations.

### Alternative B: Single `api` Schema With Default Table Grants + Restricted Function Execution

**Description**
Maintain only an `api` schema. Grant **table privileges by default** to `anon`/`authenticated` (with RLS as the real gate), but **do not grant function/procedure execution by default**; instead restrict execute privileges and require explicit grants for executable objects.

**Security**

* Good for data access if RLS is reliable; schema-level defaults reduce exposure foot-guns for tables.
* Stronger control over code execution: functions/procedures are not callable unless explicitly granted.
* Still relies on RLS discipline; missing RLS remains a serious risk if table privileges are broadly granted.

**Declarative Compatibility**

* High for tables/views (structure + predictable defaults align with declarative diffs).
* Medium for functions: executable objects still require an explicit permission step, which can reintroduce some drift if not automated/tested.

**Supabase Compatibility**

* High.
* Typically compatible as long as `public` and Supabase system schemas/roles are not globally hardened.

### Alternative C: `api` + `private` Schemas With Default Privileges (Zone-Based Least Privilege)

**Description**
Use an `api` schema accessible to `anon`/`authenticated`/`service_role` and a separate `private` schema accessible only to `service_role` (and `postgres`). Grant **usage and object privileges by default within each zone** to the roles intended to use that zone.

**Security**

* Strong defense in depth: schema boundaries prevent accidental exposure of internal objects.
* Broad defaults inside a zone are safer because the zone itself is restricted.
* RLS remains mandatory for `api` tables; missing RLS is still a major risk, but schema boundaries reduce blast radius.
* Avoiding `SECURITY DEFINER` in `api` reduces privilege escalation risk.

**Declarative Compatibility**

* High.
* Security posture is structural (object placement + default privileges), aligning well with declarative schema diffs and automated migrations.
* Minimal per-object permission bookkeeping, reducing drift risk.

**Supabase Compatibility**

* High.
* Keeps Supabase system schemas and roles intact; isolates application objects without global lockdown.
* Known edge case: objects created via Dashboard (often owned by `supabase_admin`) may not inherit the intended defaults and should be detected by CI checks.

---

## Decision

We adopt a **Zone-Based Least-Privilege Security Model** designed to work with declarative schemas and automated migrations. The core principle is that **permissions are defined by schema placement and default privilege rules**, not by per-object grants embedded in migrations.

---

## Architecture

### 1. Schema Segmentation

Schemas will be accessible to users as follows:

| Role          | `api` schema | `private` schema |
| ------------- | :----------: | :--------------: |
| postgres      |    owner     |      owner       |
| service_role  |   granted    |     granted      |
| authenticated |   granted    |                  |
| anon          |   granted    |                  |

### 2. Default Privileges

Any role that has access to a schema is assumed to have ALL necessary permissions for objects in that schema, viz.:

| Object                            | Privileges                     | Default |
| --------------------------------- | ------------------------------ | :-----: |
| schema                            | usage                          |   yes   |
| tables, views, materialized views | select, insert, update, delete |   yes   |
| sequences                         | usage, select                  |   yes   |
| functions                         | execute                        |   yes   |
| procedures                        | execute                        |   yes   |
| types                             | usage                          |   yes   |

### 3. Search Path Hardening

The `search_path` for all application roles (`anon`, `authenticated`, `service_role`) must be explicitly set. It should start with `api` and must NOT include `public`.

### 4. Automated Tests

Automated tests are an integral part of this security model; deployment should be blocked unless the automated tests have verified that:

* All tables in `api` have RLS enabled
* No `SECURITY DEFINER` functions exist in `api`
* All monitored roles have `search_path` explicitly restricted
* No unauthorized roles have `USAGE` on the `private` schema

## Consequences

### Positive

* **Improves clarity for Development**
  User-accessible data and functions go in "api", while server-side data and functions go in "private".

* **Supports automated migrations from declarative schema**
  Most automated migrations should work as expected without the need for manual adjustments.

* **Automated tests enforce schema practices**
  Deployment will be blocked if any table is created without RLS policies, or if any "security definer" functions are exposed.

* **Platform Compatibility**
  Supabase-managed roles and extensions remain untouched, preserving dashboard and upgrade stability.

### Negative / Risks

* **Ownership Edge Cases**
  This strategy assumes that all tables and functions will be managed ONLY by database migrations, mainly through the declarative schema workflow. Objects created via the Supabase Dashboard (owned by `supabase_admin`) may bypass default privileges and introduce security vulnerabilities.

* **Initial Setup Complexity**
  Requires a one-time configuration of schemas, roles, and default privileges.

## Non-Goals

* This architecture does not attempt to fully harden Supabase system schemas.
* This ADR does not prescribe application-layer authorization patterns.
* This model does not eliminate the need for RLS, but emphasizes its importance.
* Postgres Domains are not addressed by this ADR.
* This ADR does not address any objects created via the Supabase dashboard.
