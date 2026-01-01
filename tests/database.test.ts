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
  await supabaseTests.ensureRLSEnabledForTablesAndMaterializedViews('api');
});

test('no functions in the api schema should be "security definer"', async () => {
  await supabaseTests.ensureNoSecurityDefinersRoutines('api');
});

test('the users for the api schema should be anon, authenticated, service_role, postgres', async () => {
  await supabaseTests.assertAllRolesWithAccessToSchema('api', ['anon', 'authenticated', 'service_role', 'postgres', ...defaultRoles]);
});
test('the users for the private schema should be service_role, postgres', async () => {
  await supabaseTests.assertAllRolesWithAccessToSchema('private', ['service_role', 'postgres', ...defaultRoles]);
})

test('only service_role and postgres should have execute permission on private schema functions', async () => {
  await supabaseTests.assertAllRolesWithExecutePermission('private', ['service_role', 'postgres']);
}); 

test.for(['anon','authenticated','service_role'])('search_path should not include public', async (role) => {
  await supabaseTests.ensureSearchPathDoesNotIncludePublic(role);
});
