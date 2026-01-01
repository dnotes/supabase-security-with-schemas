// =============================================================================
// LIBRARY TESTS
// =============================================================================
//
// This file contains the tests for the LIBRARY of test functions; it ensures
// that they actually test what they should be testing. You should not need this
// in your project.
// =============================================================================

import { test, beforeAll, afterAll, describe, expect } from 'vitest';
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

describe.sequential('assertRLSEnabledForTablesAndMaterializedViews', async () => {

  test('the test fails if a table does not have RLS enabled', async () => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS api.test_table (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
      );
    `)  
    let error: Error | undefined;
    try {
      await supabaseTests.assertRLSEnabledForTablesAndMaterializedViews('api');
    }
    catch (err) {
      error = err as Error;
    }
    expect(error).toBeDefined();
  })

  test('the test passes if a table has RLS enabled', async () => {
    await client.query(`
      ALTER TABLE api.test_table ENABLE ROW LEVEL SECURITY;
    `)
    await supabaseTests.assertRLSEnabledForTablesAndMaterializedViews('api');
  })

  test('the test passes if a materialized view does not have RLS enabled', async () => {
    await client.query(`
      CREATE MATERIALIZED VIEW IF NOT EXISTS api.test_materialized_view AS
      SELECT 1 AS id, 'test' AS name;
    `)
    await supabaseTests.assertRLSEnabledForTablesAndMaterializedViews('api');
  })

  afterAll(async () => {
    await client.query(`
      DROP TABLE IF EXISTS api.test_table;
      DROP MATERIALIZED VIEW IF EXISTS api.test_materialized_view;
    `)
  })
  
})

describe.sequential('assertNoSecurityDefinersRoutines', async () => {
  test('the test fails if a function has a security definer', async () => {
    await client.query(`
      CREATE OR REPLACE FUNCTION api.test_function() 
      RETURNS void 
      LANGUAGE plpgsql 
      SECURITY DEFINER
      AS $$
      BEGIN
      END;
      $$;
    `)
    let error: Error | undefined;
    try {
      await supabaseTests.assertNoSecurityDefinersRoutines('api');
    }
    catch (err) {
      error = err as Error;
    }
    expect(error).toBeDefined();
  })

  test('the test passes if a function does not have a security definer', async () => {
    await client.query(`
      CREATE OR REPLACE FUNCTION api.test_function() 
      RETURNS void 
      LANGUAGE plpgsql 
      AS $$
      BEGIN 
      END;
      $$;
    `)
    await supabaseTests.assertNoSecurityDefinersRoutines('api');
  })

  test('the test fails if a procedure has a security definer', async () => {
    await client.query(`
      CREATE OR REPLACE PROCEDURE api.test_procedure() 
      LANGUAGE plpgsql
      SECURITY DEFINER
      AS $$
      BEGIN
      END;
      $$;
    `)
    let error: Error | undefined
    try {
      await supabaseTests.assertNoSecurityDefinersRoutines('api');
    }
    catch (err) {
      error = err as Error;
    }
    expect(error).toBeDefined();
  })

  test('the test passes if a procedure does not have a security definer', async () => {
    await client.query(`
      CREATE OR REPLACE PROCEDURE api.test_procedure() 
      LANGUAGE plpgsql 
      AS $$
      BEGIN
      END;
      $$;
    `)
    await supabaseTests.assertNoSecurityDefinersRoutines('api');
  })

  afterAll(async () => {
    await client.query(`
      DROP FUNCTION IF EXISTS api.test_function;
      DROP PROCEDURE IF EXISTS api.test_procedure;
    `)
  })
})

describe('assertAccessToSchema', async () => {
  test('all of the proper roles have access', async () => {
    await supabaseTests.assertAccessToSchema('api', ['anon', 'authenticated', 'service_role', 'postgres', ...defaultRoles]);
  })
  test.fails('the test fails if one of the listed roles does NOT have access', async () => {
    await supabaseTests.assertAccessToSchema('api', ['invalid', 'anon', 'authenticated', 'service_role', 'postgres', ...defaultRoles]);
  })
  test.fails('the test fails if a role that is NOT in the list has access', async () => {
    await supabaseTests.assertAccessToSchema('api', ['anon', 'authenticated', /** 'service_role', */ 'postgres', ...defaultRoles]);
  })
})

describe('assertDefaultPrivilegesForTables', async () => {
  test('all of the proper roles have select privilege on all tables', async () => {
    await supabaseTests.assertDefaultPrivilegesForTables('api', ['anon', 'authenticated', 'service_role']);
  })
  test.fails('the test fails if one of the listed roles does NOT have select privilege on all tables', async () => {
    await supabaseTests.assertDefaultPrivilegesForTables('api', ['invalid', 'anon', 'authenticated', 'service_role']);
  })
  test.fails('the test fails if a role that is NOT in the list has select privilege on all tables', async () => {
    await supabaseTests.assertDefaultPrivilegesForTables('api', ['anon', 'authenticated']);
  })
})

describe('assertDefaultPrivilegesForRoutines', async () => {
  test('all of the proper roles have execute permission', async () => {
    await supabaseTests.assertDefaultPrivilegesForRoutines('api', ['anon', 'authenticated', 'service_role']);
  })
  test.fails('the test fails if a role does not have execute permission', async () => {
    await supabaseTests.assertDefaultPrivilegesForRoutines('api', ['invalid', 'anon', 'authenticated', 'service_role']);
  })
  test.fails('the test passes if a role has execute permission', async () => {
    await supabaseTests.assertDefaultPrivilegesForRoutines('api', ['anon', 'authenticated']);
  })
})

describe('assertValidSearchPath', async () => {
  test('the test fails if there is no explicit search path', async () => {
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'test_search_path_role') THEN
          CREATE ROLE test_search_path_role LOGIN;
        END IF;
      END
      $$;
    `);
    let error:Error|undefined
    try {
      await supabaseTests.assertValidSearchPath('test_search_path_role');
    }
    catch(err) {
      error = err as Error
    }
    expect(error).toBeDefined()
  })
  test('the test passes if the search path is set and does not include public', async() => {
    await client.query(`
      ALTER ROLE test_search_path_role SET search_path = 'api,extensions';
    `);
    await supabaseTests.assertValidSearchPath('test_search_path_role');    
  })
  test('the test fails if the search path includes public', async () => {
    // create a role with a proper explicit search path
    await client.query(`
      ALTER ROLE test_search_path_role SET search_path = 'public,extensions';
    `);
    let error:Error|undefined
    try {
      await supabaseTests.assertValidSearchPath('test_search_path_role');
    }
    catch(err) {
      error = err as Error
    }
    expect(error).toBeDefined()    
  })
  afterAll(async()=>{
    await client.query(`
      DROP ROLE IF EXISTS test_search_path_role;
    `);
  })
})

describe('assertNoTablesWithExtraRoles', async () => {
  test('creating a table does NOT give it extra roles', async () => {
    await client.query(`
      CREATE TABLE api.test_table (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
      );
    `);
    await supabaseTests.assertNoTablesWithExtraRoles('api', ['anon', 'authenticated', 'service_role', 'postgres']);
  })
  test('the test fails if a table has extra roles', async () => {
    await client.query(`
      GRANT SELECT ON TABLE api.test_table TO supabase_read_only_user;
    `)
    let error:Error|undefined
    try {
      await supabaseTests.assertNoTablesWithExtraRoles('api', ['anon', 'authenticated', 'service_role', 'postgres']);
    }
    catch(err) {
      error = err as Error
    }
    expect(error).toBeDefined();
  })
  afterAll(async()=>{
    await client.query(`
      DROP TABLE IF EXISTS api.test_table;
    `);
  })
})

describe('assertNoRoutinesWithExtraRoles', async () => {
  test('creating a routine does NOT give it extra roles', async () => {
    await client.query(`
      CREATE FUNCTION api.test_function() 
      RETURNS void 
      LANGUAGE plpgsql 
      AS $$
      BEGIN
      END;
      $$;
    `);
    await supabaseTests.assertNoRoutinesWithExtraRoles('api', ['anon', 'authenticated', 'service_role', 'postgres']);
  })
  test('the test fails if a routine has extra roles', async () => {
    await client.query(`
      GRANT EXECUTE ON FUNCTION api.test_function() TO supabase_read_only_user;
    `)
    let error:Error|undefined
    try {
      await supabaseTests.assertNoRoutinesWithExtraRoles('api', ['anon', 'authenticated', 'service_role', 'postgres']);
    }
    catch(err) {
      error = err as Error
    }
    expect(error).toBeDefined();
  })
  afterAll(async()=>{
    await client.query(`
      DROP FUNCTION IF EXISTS api.test_function;
    `);
  })
})