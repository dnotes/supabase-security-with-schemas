import { expect } from 'vitest';
import type { Client } from 'pg';

export class SupabaseTests {
  private client: Client;

  constructor(client: Client) {
    this.client = client;
  }

  async setup() {
    await this.client.connect();
  }
  
  async teardown() {
    await this.client.end();
  }

  async assertRLSEnabledForTablesAndMaterializedViews(schema:string) {
    // This SQL query selects the names of tables and materialized views in the 'api' schema
    // where RLS is NOT enabled (relrowsecurity is false).
    // Note: Regular views (relkind = 'v') cannot have RLS and inherit security from base tables.
    const query = `
      SELECT
        c.relname AS table_name,
        CASE c.relkind
          WHEN 'r' THEN 'table'
          WHEN 'm' THEN 'materialized view'
        END AS object_type
      FROM
        pg_catalog.pg_class c
      JOIN
        pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE
        n.nspname = $1
        AND c.relkind IN ('r', 'm') -- 'r' = table, 'm' = materialized view
        AND c.relrowsecurity IS FALSE;
    `;
  
    try {
      const res = await this.client.query(query, [schema]) as { rows: { table_name: string, object_type: string }[] };
      const objectsWithoutRLS = res.rows.map(row => `${row.table_name} (${row.object_type})`);
  
      // If objectsWithoutRLS is empty, the test passes.
      // If it contains any names, the test fails, and we list them.
      expect(objectsWithoutRLS.length, `Objects without RLS:\n  ${objectsWithoutRLS.join('\n  ')}\n`).toBe(0);
  
    } catch (err) {
      throw err;
    }
  }

  async assertNoSecurityDefinersRoutines(schema:string) {
    const query = `
      SELECT routine_name FROM information_schema.routines
      WHERE routine_schema = $1
      AND security_type = 'DEFINER';
    `;
    const res = await this.client.query(query, [schema]) as { rows: { routine_name: string }[] };
    const routines = res.rows.map(row => row.routine_name);
    expect(routines.length).toBe(0);
  }

  async assertAccessToSchema(schema:string, roles:string[]) {
    const query = `
      SELECT rolname
      FROM pg_roles
      WHERE has_schema_privilege(rolname, $1, 'USAGE')
      ORDER BY rolname ASC;
    `;
    const res = await this.client.query(query, [schema]) as { rows: { rolname: string }[] };
    const grantees = res.rows.map(row => row.rolname);
    expect(grantees).toEqual(roles.sort());
  }

  async assertDefaultPrivilegesForTables(schema:string, roles:string[]) {
    const query = `
      SELECT DISTINCT
        acl.grantee::regrole::text AS grantee
      FROM pg_catalog.pg_default_acl d
      JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
      CROSS JOIN LATERAL aclexplode(d.defaclacl) AS acl
      WHERE n.nspname = $1
        AND d.defaclobjtype = 'r'
        AND acl.privilege_type = 'SELECT'
      ORDER BY grantee ASC;
    `;
    const res = await this.client.query(query, [schema]) as { rows: { grantee: string }[] };
    const grantees = res.rows.map(row => row.grantee);
    expect(grantees).toEqual(roles.sort());
  }

  async assertNoTablesWithExtraRoles(schema:string, roles:string[]) {
    // Get all tables in the schema and ensure only the provided roles have privileges
    const query = `
      SELECT
        t.table_name,
        grantee,
        privilege_type
      FROM information_schema.table_privileges t
      WHERE t.table_schema = $1
      ORDER BY t.table_name, grantee
    `;
    const res = await this.client.query(query, [schema]) as { rows: { table_name: string, grantee: string, privilege_type: string }[] };

    // For each table, get a set of grantees who are NOT in the allowed roles
    const allowedRolesSet = new Set(roles.map(r => r.toLowerCase()));
    const extras: { table: string, grantee: string, privilege: string }[] = [];
    for (const row of res.rows) {
      const grantee = row.grantee.toLowerCase();
      if (!allowedRolesSet.has(grantee)) {
        extras.push({
          table: row.table_name,
          grantee: row.grantee,
          privilege: row.privilege_type
        });
      }
    }

    expect(extras.length, `Extra privileges found:\n${extras.map(e => `  Table "${e.table}" has "${e.privilege}" granted to "${e.grantee}"`).join('\n')}\n`).toBe(0);
  }

  async assertDefaultPrivilegesForRoutines(schema:string, roles:string[]) {
    const query = `
      SELECT DISTINCT
        acl.grantee::regrole::text AS grantee
      FROM pg_catalog.pg_default_acl d
      JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
      CROSS JOIN LATERAL aclexplode(d.defaclacl) AS acl
      WHERE n.nspname = $1
        AND d.defaclobjtype IN ('f', 'p')
        AND acl.privilege_type = 'EXECUTE'
      ORDER BY grantee ASC;
    `;

    const res = await this.client.query(query, [schema]) as { rows: { grantee: string }[] };
    const grantees = res.rows.map(row => row.grantee);
    expect(grantees).toEqual(roles.sort());
  }

  async assertNoRoutinesWithExtraRoles(schema:string, roles:string[]) {
    // Get all routines (functions and procedures) in the schema and their privileges
    const query = `
      SELECT
        p.proname AS routine_name,
        acl.grantee::regrole::text AS grantee,
        acl.privilege_type
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      LEFT JOIN LATERAL aclexplode(p.proacl) AS acl ON TRUE
      WHERE n.nspname = $1
      ORDER BY p.proname, grantee
    `;
    const res = await this.client.query(query, [schema]) as { rows: { routine_name: string, grantee: string | null, privilege_type: string | null }[] };

    const allowedRolesSet = new Set(roles.map(r => r.toLowerCase()));
    const extras: { routine: string, grantee: string, privilege: string }[] = [];
    for (const row of res.rows) {
      // grantee can be null if there are no explicit grants
      if (row.grantee && row.privilege_type) {
        const grantee = row.grantee.toLowerCase();
        if (!allowedRolesSet.has(grantee)) {
          extras.push({
            routine: row.routine_name,
            grantee: row.grantee,
            privilege: row.privilege_type
          });
        }
      }
    }

    expect(
      extras.length,
      `Extra routine privileges found:\n${extras.map(
        e => `  Routine "${e.routine}" has "${e.privilege}" granted to "${e.grantee}"`
      ).join('\n')}\n`
    ).toBe(0);
  }

  async assertValidSearchPath(role:string) {
    const query = `
      SELECT
        s.setconfig
      FROM pg_db_role_setting s
      JOIN pg_roles r ON r.oid = s.setrole
      WHERE r.rolname = $1
    `;
    const res = await this.client.query(query, [role]) as { rows: { setconfig: string[] }[] };
  
    // 1. Verify that a custom search_path is actually set for this role
    expect(res.rows.length).toBeGreaterThan(0);

    const config = res.rows[0]!.setconfig || [];
    const searchPathEntry = config.find(c => c.toLowerCase().startsWith('search_path='));

    // 2. Ensure the search_path setting exists in the role config
    expect(searchPathEntry).toBeDefined();

    // 3. Logic Check: Must contain 'api' and MUST NOT contain 'public'
    const pathValue = (searchPathEntry as string).split('=')[1]!;
    const schemas = pathValue.replace(/["']/g,'').split(',').map(s => s.trim().toLowerCase());

    expect(schemas).toContain('api');
    expect(schemas).not.toContain('public');
  }
}