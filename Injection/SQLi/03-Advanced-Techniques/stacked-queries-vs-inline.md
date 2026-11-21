# Stacked Queries vs. Inline Expressions
 
## The Distinction
 
Every injection technique covered elsewhere in this repository — UNION attacks, boolean conditions, error-based extraction, time delays — can be delivered through one of two fundamentally different mechanisms, and confusing them is a common source of "my syntactically correct payload still doesn't execute" failures.
 
**Inline expression injection** appends attacker-controlled logic as part of the *same* statement the application originally intended to execute — a sub-expression, an additional `OR`/`AND` clause, an appended `UNION SELECT`. The database still only executes **one statement**; the attacker has merely altered its logical structure.
 
```sql
-- Original
SELECT * FROM tracking WHERE id = 'INPUT'
 
-- Inline injection: still one statement
SELECT * FROM tracking WHERE id = 'x' AND (SELECT pg_sleep(5))--'
```
 
**Stacked queries** (also called "query piggybacking" or "batched queries") terminate the original statement entirely and append a **second, fully independent statement**, separated by a semicolon:
 
```sql
SELECT * FROM tracking WHERE id = 'x'; SELECT pg_sleep(5)--'
```
 
This is not a stylistic variant of the same attack — it is a structurally different capability with a materially larger attack surface, because a stacked second statement is **not constrained to be a `SELECT` at all**. It can be `INSERT`, `UPDATE`, `DELETE`, `DROP`, or a call to an administrative stored procedure, none of which are expressible as an inline sub-expression within a `SELECT`-based query.
 
## Driver and API-Level Gating
 
Whether stacked queries are available to an attacker is **not purely a function of the DBMS's SQL dialect** — it is gated by whether the application's database driver/API submits the raw query string to the engine in a way that permits multiple statements per call.
 
| Environment | Stacked Query Support |
|---|---|
| **MSSQL** (most drivers, including ADO.NET, ODBC) | Generally supported by default |
| **PostgreSQL** (via most standard drivers, e.g., `libpq`-based clients) | Generally supported |
| **MySQL** (via most APIs/drivers) | Frequently **disabled by default** — many client libraries (e.g., PHP's `mysqli` in default configuration) explicitly submit one statement per call and will error or silently ignore anything after the first semicolon unless `multi_query`-style functions are explicitly used by the application |
| **Oracle** | PL/SQL anonymous blocks can achieve a stacked-query-like effect (`BEGIN ... END;`), but true ANSI-style semicolon-stacking at the driver level is uncommon |
 
This means **stacked-query viability must be empirically tested per target**, not assumed from the DBMS alone. A reliable test: inject a syntactically trivial second statement with an observable side effect (a deliberate, harmless delay via a stacked `WAITFOR DELAY` or `SELECT pg_sleep(n)`) and observe whether it executes.
 
## Why Stacked Queries Matter Disproportionately
 
The practical significance of confirmed stacked-query support is that it converts a **read-only data-extraction bug into a far broader compromise primitive**:
 
- **Data modification/destruction**: `'; UPDATE users SET password='attacker-controlled' WHERE username='administrator'--` or outright `DROP TABLE` statements become possible, not just data *reads*.
- **Privilege and account manipulation**: `'; INSERT INTO users (username, password, role) VALUES ('backdoor','pass','admin')--`
- **OS-level escalation (MSSQL specifically)**: `'; EXEC xp_cmdshell 'whoami'--` — if `xp_cmdshell` is enabled (historically on by default in older MSSQL versions, though disabled by default since SQL Server 2005+), this is a direct pivot from SQL injection to **arbitrary operating system command execution**.
This is why confirming stacked-query support, even in an assessment where the initial finding was "only" a blind boolean oracle, should always be treated as a priority escalation step — the severity delta between "I can read your users table" and "I can execute arbitrary OS commands on your database server" is enormous, and both can originate from the exact same injection point.
 
## Delivery Considerations: Encoding the Semicolon
 
In contexts where the injection point is transmitted via a URL, cookie, or header, the literal semicolon character (`;`) that separates stacked statements must be correctly percent-encoded (`%3B`) to survive transport without being misinterpreted by an intermediate layer (some frameworks use literal semicolons as a delimiter in cookie or query-string parsing, e.g., historical `;`-separated path parameters or cookie attribute separators) before it ever reaches the database layer intact:
 
```
Cookie: TrackingId=x'%3BSELECT+pg_sleep(10)--
```
 
Failure to encode the semicolon correctly is a common, easily overlooked reason a conceptually valid stacked-query payload fails — the request layer may be silently truncating or misparsing the payload before the application even constructs the SQL string.
 
## Stacked Queries Combined with Conditional Logic
 
Stacked queries are not limited to simple sequential statements — the second statement can itself contain the full conditional logic used in boolean- or time-based blind extraction, giving a cleaner separation between the original query (left entirely undisturbed and syntactically valid) and the attacker's independent logic:
 
```sql
x'; SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a')
      THEN pg_sleep(10) ELSE pg_sleep(0) END
    FROM users--
```
 
Note the placement discipline required here: the table reference (`FROM users`) and any row-scoping clause (`WHERE ...`, if used outside the `CASE`) must appear in the correct position relative to the `CASE` expression for the statement to parse — a frequent source of syntax errors when constructing these payloads is misplacing the `FROM` clause relative to the conditional block.
 
## Practical Lab Verification
 
- [Lab 15 — Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)
 
