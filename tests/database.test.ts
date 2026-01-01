// =============================================================================
// DATABASE TESTS
// =============================================================================
//
// This file contains the tests for the standard database setup security model.
// You should be able to copy this file to a new repository and it should work.
// =============================================================================

import { test, beforeAll, afterAll } from 'vitest';
import { SupabaseTests } from '../src/index.js';
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
let supabaseTests: SupabaseTests;

beforeAll(async () => {
  client = new Client(dbConfig);
  await client.connect();
  supabaseTests = new SupabaseTests(client);
});

afterAll(async () => {
  await client.end();
});

test('all tables and materialized views in the API schema should have RLS enabled', async () => {
  await supabaseTests.assertRLSEnabledForTablesAndMaterializedViews('api');
});

test('no functions in the api schema should be "security definer"', async () => {
  await supabaseTests.assertNoSecurityDefinersRoutines('api');
});

test('the users for the api schema should be anon, authenticated, service_role, postgres', async () => {
  await supabaseTests.assertAccessToSchema('api', ['anon', 'authenticated', 'service_role', 'postgres', ...defaultRoles]);
});
test('the users for the private schema should be service_role, postgres', async () => {
  await supabaseTests.assertAccessToSchema('private', ['service_role', 'postgres', ...defaultRoles]);
})


// TABLES
test('no tables in the api schema should have users outside of the listed ones', async () => {
  await supabaseTests.assertNoTablesWithExtraRoles('api', ['anon', 'authenticated', 'service_role', 'postgres']);
})
test('default privileges in the api schema should be set', async () => {
  await supabaseTests.assertDefaultPrivilegesForTables('api', ['anon', 'authenticated', 'service_role']);
});
test('no tables in the private schema should have users outside of the lised ones', async () => {
  await supabaseTests.assertNoTablesWithExtraRoles('private', ['service_role']);
})
test('default privileges in the private schema should be set', async () => {
  await supabaseTests.assertDefaultPrivilegesForTables('private', ['service_role']);
});

test('no routines in the api schema should have users outside of the listed ones', async () => {
  await supabaseTests.assertNoRoutinesWithExtraRoles('api', ['anon', 'authenticated', 'service_role', 'postgres']);
})
test('default privileges should be set correctly for routines in the api schema', async () => {
  await supabaseTests.assertDefaultPrivilegesForRoutines('api', ['anon', 'authenticated', 'service_role']);
});
test('no routines in the private schema should have users outside of the listed ones', async () => {
  await supabaseTests.assertNoRoutinesWithExtraRoles('private', ['service_role']);
})
test('default privileges should be set correctly for routines in the private schema', async () => {
  await supabaseTests.assertDefaultPrivilegesForRoutines('private', ['service_role']);
}); 

test.for(['anon','authenticated','service_role'])('search_path should not include public', async (role) => {
  await supabaseTests.assertValidSearchPath(role);
});
