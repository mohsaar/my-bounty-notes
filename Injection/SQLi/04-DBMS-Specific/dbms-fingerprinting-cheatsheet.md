# DBMS Fingerprinting Cheat Sheet
 
Identifying the backend DBMS early determines every subsequent exploitation decision: comment syntax, metadata views, string functions, and available delay/OOB mechanisms are all DBMS-specific. This page is a fast-reference lookup; see the individual DBMS pages in this directory for full depth.
 
## Version Disclosure Functions
 
| DBMS | Version Query | Requires `FROM` clause? |
|---|---|---|
| MySQL | `SELECT @@version` | No |
| PostgreSQL | `SELECT version()` | No |
| MSSQL | `SELECT @@version` | No |
| Oracle | `SELECT banner FROM v$version` | Yes (or `FROM dual` for other literal queries) |
 
## Comment Syntax
 
| DBMS | Comment Token(s) | Notes |
|---|---|---|
| MySQL | `#` or `-- ` (trailing space required) | `--` without a following space is not recognized as a comment |
| PostgreSQL | `--` or `/* */` | Standard ANSI behavior |
| MSSQL | `--` or `/* */` | Standard ANSI behavior |
| Oracle | `--` or `/* */` | Standard ANSI behavior |
 
## String Concatenation
 
See `01-Fundamentals/02-string-concat-nuances.md` for the full breakdown (`CONCAT()` for MySQL, `||` for PostgreSQL/Oracle/SQLite, `+` for MSSQL).
 
## Schema/Metadata Enumeration
 
| DBMS | Table Listing | Column Listing |
|---|---|---|
| MySQL / PostgreSQL / MSSQL | `information_schema.tables` | `information_schema.columns` |
| Oracle | `all_tables` (or `user_tables`, `dba_tables`) | `all_tab_columns` (or `user_tab_columns`, `dba_tab_columns`) |
 
## Time-Delay Functions (Blind Injection)
 
| DBMS | Function | Notes |
|---|---|---|
| MySQL | `SLEEP(N)` | Directly usable inside a boolean expression |
| PostgreSQL | `pg_sleep(N)` | Requires subquery/`SELECT` context |
| MSSQL | `WAITFOR DELAY '0:0:N'` | Statement, not a function — typically requires stacked-query context |
| Oracle | `DBMS_LOCK.SLEEP(N)` (privilege-gated) or heavy computational delay fallback | Less reliably available than the other three |
 
## Error-Based Extraction Functions
 
| DBMS | Function |
|---|---|
| MySQL | `EXTRACTVALUE()`, `UPDATEXML()` |
| PostgreSQL | `CAST(... AS int)` |
| MSSQL | `CONVERT(int, ...)` |
| Oracle | `TO_CHAR(1/0)` inside a `CASE` (conditional/induced errors); verbose extraction less reliable by default |
 
## Quick Decision Flow
 
1. Try a bare `UNION SELECT NULL,NULL--` (or `,NULL,NULL` incrementing). If this **fails with a syntax error** while other signals (boolean logic) suggest the point is live → suspect **Oracle**, retry with `FROM dual`.
2. Try `SELECT @@version` vs `SELECT version()` — a successful `@@version` suggests **MySQL or MSSQL**; a successful `version()` suggests **PostgreSQL or MySQL**. Cross-check with comment syntax (`#` working confirms MySQL) and `information_schema` behavior to disambiguate.
3. Once the DBMS is confirmed, switch immediately to that DBMS's specific function set for all subsequent extraction, timing, and OOB payloads — do not continue probing with generic/ANSI syntax once fingerprinting is complete.
## Full DBMS-Specific Guides
 
- [MySQL](mysql.md)
- [PostgreSQL](postgresql.md)
- [MSSQL](mssql.md)
- [Oracle](oracle.md)
 
