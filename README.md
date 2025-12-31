# Supabase Setup

This repository is an exploration of some ideas related to setting up a Supabase project that appropriately balances ease of development with strong security. Here are the basic principles:

1. Don't use the public schema, use "api".

2. Have a separate schema for "private" functions and data, accessible only to service_role.

3. Using declarative schema files really seems desirable, but grants and permissions fail to transfer with the current tooling. To avoid constant manual editing of generated migrations (a source of drift) I think:

  - Schema usage, table and sequence permissions (select, insert, etc.) and function execution permissions should be treated as a prerequisite for access, not a granular security layer. All those permissions should be granted to roles on a per-schema basis. Row-Level Security should be the only granular access permission strategy.

  - The "api" schema should be accessible by "anon", "authenticated", and "service_role".

  - The "private" schema should be accessible by "service_role".

1. Every table in the "api" schema should be required to have RLS enabled. This should be enforced by an automated test that blocks delivery if it fails in CI.

5. The search path should be set for each of the common roles, and this should also be enforced by an automated test.

