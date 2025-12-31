import { test, expect, beforeAll, afterAll } from 'vitest';
import { Client } from 'pg';

const dbConfig = {
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  port: parseInt(process.env.DB_PORT || '54322', 10),
};

const defaultRoles = [
  'pg_read_all_data',
  'pg_write_all_data',
  'supabase_etl_admin',
  'supabase_admin',
  'supabase_read_only_user',
]

let client:Client;

beforeAll(async () => {
  client = new Client(dbConfig);
  await client.connect();
});

afterAll(async () => {
  await client.end();
});

export async function ensureRLSEnabledForTablesAndMaterializedViews(schema:string) {
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
    const res = await client.query(query, [schema]) as { rows: { table_name: string, object_type: string }[] };
    const objectsWithoutRLS = res.rows.map(row => `${row.table_name} (${row.object_type})`);

    // If objectsWithoutRLS is empty, the test passes.
    // If it contains any names, the test fails, and we list them.
    expect(objectsWithoutRLS.length, `Objects without RLS:\n  ${objectsWithoutRLS.join('\n  ')}\n`).toBe(0);

  } catch (err) {
    throw err;
  }
}

test('all tables and materialized views in the API schema should have RLS enabled', async () => {
  await ensureRLSEnabledForTablesAndMaterializedViews('api');
});

export async function ensureNoSecurityDefinersRoutines(schema:string) {
  const query = `
    SELECT routine_name FROM information_schema.routines
    WHERE routine_schema = $1
    AND security_type = 'DEFINER';
  `;
  const res = await client.query(query, [schema]) as { rows: { routine_name: string }[] };
  const routines = res.rows.map(row => row.routine_name);
  expect(routines.length).toBe(0);
}

test('no functions in the api schema should be "security definer"', async () => {
  await ensureNoSecurityDefinersRoutines('api');
});

export async function assertAllRolesWithAccessToSchema(schema:string, roles:string[]) {
  const query = `
    SELECT rolname
    FROM pg_roles
    WHERE has_schema_privilege(rolname, $1, 'USAGE')
    ORDER BY rolname ASC;
  `;
  const res = await client.query(query, [schema]) as { rows: { rolname: string }[] };
  const grantees = res.rows.map(row => row.rolname);
  expect(grantees).toEqual(roles.sort());
}
test('the users for the api schema should be anon, authenticated, service_role, postgres', async () => {
  await assertAllRolesWithAccessToSchema('api', ['anon', 'authenticated', 'service_role', 'postgres', ...defaultRoles]);
});
test('the users for the private schema should be service_role, postgres', async () => {
  await assertAllRolesWithAccessToSchema('private', ['service_role', 'postgres', ...defaultRoles]);
})

export async function assertAllRolesWithExecutePermission(schema:string, roles:string[]) {
  const query = `
    SELECT DISTINCT grantee FROM information_schema.routine_privileges
    WHERE routine_schema = $1
    AND privilege_type = 'EXECUTE'
    ORDER BY grantee ASC;
  `;

  const res = await client.query(query, [schema]) as { rows: { grantee: string }[] };
  const grantees = res.rows.map(row => row.grantee);
  expect(grantees).toEqual(roles.sort());
}
test('only service_role and postgres should have execute permission on private schema functions', async () => {
  await assertAllRolesWithExecutePermission('private', ['service_role', 'postgres']);
}); 

export async function ensureSearchPathDoesNotIncludePublic(role:string) {
  const query = `
    SELECT
      s.setconfig
    FROM pg_db_role_setting s
    JOIN pg_roles r ON r.oid = s.setrole
    WHERE r.rolname = $1
  `;
  const res = await client.query(query, [role]) as { rows: { setconfig: string[] }[] };
 
  // 1. Verify that a custom search_path is actually set for this role
  expect(res.rows.length).toBeGreaterThan(0);

  const config = res.rows[0]!.setconfig || [];
  const searchPathEntry = config.find(c => c.toLowerCase().startsWith('search_path='));

  // 2. Ensure the search_path setting exists in the role config
  expect(searchPathEntry).toBeDefined();

  // 3. Logic Check: Must contain 'api' and MUST NOT contain 'public'
  const pathValue = (searchPathEntry as string).split('=')[1]!;
  const schemas = pathValue.split(',').map(s => s.trim().toLowerCase());

  expect(schemas).toContain('api');
  expect(schemas).not.toContain('public');
}
test.for(['anon','authenticated','service_role'])('search_path should not include public', async (role) => {
  await ensureSearchPathDoesNotIncludePublic(role);
});
