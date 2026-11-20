# String Concatenation Nuances: `||` vs `+` vs `CONCAT()`
 
## Why This Matters to an Attacker
 
Every SQL injection technique beyond the most trivial tautology eventually runs into a structural constraint: **the application only reflects, or only accepts, one output channel** — one visible column, one error message string, one DNS label. Real schemas rarely hand you credentials pre-packaged into a single field; usernames and passwords live in separate columns. To exfiltrate more than one piece of data through a single-value channel, an attacker must **fold multiple columns into one string** at the database layer before the result ever reaches the constrained output channel.
 
This single operation — string concatenation — is arguably the most load-bearing primitive in practical SQLi exploitation. It appears in:
- UNION-based extraction when only one column is reflected or exists in the result set
- Error-based exfiltration, where the induced error message has room for exactly one string
- Out-of-band exfiltration, where data must be smuggled into a single DNS label or HTTP path
- WAF/filter bypass, where fragmenting a blocked keyword across concatenated string literals defeats signature matching
Getting the concatenation syntax wrong is one of the most common reasons a conceptually correct payload fails outright — and because the exact operator is DBMS-specific, this is also a reliable **fingerprinting signal** in its own right.
 
## Syntax by DBMS
 
| DBMS | Operator / Function | Example | Notes |
|---|---|---|---|
| **MySQL** | `CONCAT(a, b, ...)` | `CONCAT(username,'~',password)` | MySQL does **not** support `||` as concatenation by default — in standard SQL mode, `||` is interpreted as logical OR. (If `PIPES_AS_CONCAT` SQL mode is enabled, `||` behaves like concatenation, but assume it isn't unless proven otherwise.) `CONCAT_WS(sep, a, b, ...)` is a useful variant that inserts a separator automatically between every argument. |
| **PostgreSQL** | `||` | `username || '~' || password` | Standard ANSI concatenation operator. `CONCAT()` also exists as a function in modern PostgreSQL versions as a convenience alias. |
| **Oracle** | `||` | `username || '~' || password` | Same operator as PostgreSQL — both are closer to ANSI SQL in this respect. `CONCAT(a,b)` also exists but (notably) only accepts **two** arguments, making `||` the practical choice for folding 3+ values. |
| **MSSQL** | `+` | `username + '~' + password` | MSSQL overloads the arithmetic `+` operator for both numeric addition and string concatenation, inferred from operand types. `CONCAT()` is also available (SQL Server 2012+) and has the advantage of implicitly converting `NULL` to an empty string rather than making the whole expression `NULL` — relevant when a column might be nullable and you don't want one `NULL` value to silently blank out your entire exfiltration string. |
| **SQLite** | `||` | `username || '~' || password` | Follows the ANSI convention. |
 
## The Delimiter Principle
 
Concatenating values with no separator (`username || password`) produces an ambiguous, unparseable string the moment either value could contain variable length or overlapping characters (`adminpassword123` — where does the username end?). Always insert an unambiguous delimiter that is extremely unlikely to appear in the underlying data:
 
```sql
username || '~' || password
username || ':::' || password
username || CHAR(126) || password   -- CHAR(126) = '~', useful if the literal tilde is filtered
```
 
For exfiltrating **many** rows into a single reflected field (common in UNION attacks against tables with no natural row-separation in the output), concatenate an aggregate function across rows in addition to across columns:
 
```sql
-- MySQL
SELECT GROUP_CONCAT(username, '~', password SEPARATOR ',') FROM users
 
-- PostgreSQL
SELECT STRING_AGG(username || '~' || password, ',') FROM users
 
-- Oracle
SELECT LISTAGG(username || '~' || password, ',') WITHIN GROUP (ORDER BY username) FROM users
 
-- MSSQL
SELECT STRING_AGG(username + '~' + password, ',') FROM users
```
 
This lets a single-row, single-column UNION reflection point exfiltrate an **entire table** in one request — critical when the injection point is heavily rate-limited or when automation (one request per row) would be too slow or noisy.
 
## Concatenation as a WAF/Filter Evasion Primitive
 
Because concatenation operators merge string literals at **query evaluation time**, not at the time the request is parsed by upstream filters, they can be used to split a blacklisted keyword across multiple literals that individually look benign:
 
```sql
'UNI'||'ON SELECT'   -- Oracle/Postgres: evaluates to 'UNION SELECT' only inside the DB engine
```
 
A naive WAF regex scanning the raw request body for the literal substring `UNION SELECT` will not match this payload, because the keyword never appears contiguously in the transmitted request — it is only reconstructed after the database parses and evaluates the concatenation. See `05-Bypasses-and-WAF/` for the full treatment of this technique combined with encoding-based evasion.
 
## Practical Lab Verification
 
- [Lab 10 — UNION attack, retrieving multiple values in a single column](../07-PortSwigger-Labs-Writeups/in-band/lab-10-union-single-column-multiple-values.md)
- [Lab 18 — Filter bypass via XML encoding](../07-PortSwigger-Labs-Writeups/filter-bypass/lab-18-xml-encoding-filter-bypass.md)
 
