# PortSwigger SQLi Labs — Practical Lab Exercises

This section is **applied verification only**. The mechanics, DBMS nuances, and hunting methodology are taught once, in depth, in the core reference directories (`01-Fundamentals/`, `02-Vulnerability-Types/`, `03-Advanced-Techniques/`, `04-DBMS-Specific/`, `05-Bypasses-and-WAF/`, `06-Hunting-Methodology/`). Each exercise below states the objective and payload concisely, links back to the relevant core doc for the "why," and adds a tightened, exercise-specific **Bug Bounty Relevance** note.

---

## In-Band (Error-Based & UNION-Based)

| # | Exercise (Internal Write-up) | Difficulty | Core Concept & Reference | PortSwigger Lab Link |
| :--- | :--- | :--- | :--- | :--- |
| 01 | [WHERE clause hidden data](02-Vulnerability-Types/in-band/union-based.md) | Apprentice | Tautology-based filter bypass | [Open Lab](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data) |
| 02 | [Login bypass](02-Vulnerability-Types/in-band/union-based.md) | Apprentice | Comment-based auth logic bypass | [Open Lab](https://portswigger.net/web-security/sql-injection/lab-login-bypass) |
| 03 | [DBMS version — Oracle](04-DBMS-Specific/dbms-fingerprinting-cheatsheet.md) | Practitioner | `dual` table, DBMS fingerprinting | [Open Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle) |
| 04 | [DBMS version — MySQL/MSSQL](04-DBMS-Specific/dbms-fingerprinting-cheatsheet.md) | Practitioner | Comment syntax dialects, `@@version` | [Open Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft) |
| 05 | [Listing DB contents — non-Oracle](02-Vulnerability-Types/in-band/union-based.md) | Practitioner | `information_schema` enumeration | [Open Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle) |
| 06 | [Listing DB contents — Oracle](02-Vulnerability-Types/in-band/union-based.md) | Practitioner | `all_tables` / `all_tab_columns` | [Open Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle) |
| 07 | [UNION — column count](02-Vulnerability-Types/in-band/union-based.md) | Practitioner | `NULL` probing, `ORDER BY` method | [Open Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) |
| 08 | [UNION — finding a text column](02-Vulnerability-Types/in-band/union-based.md) | Practitioner | Type-compatibility & reflection | [Open Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text) |
| 09 | [UNION — retrieving data from other tables](02-Vulnerability-Types/in-band/union-based.md) | Practitioner | End-to-end extraction chain | [Open Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables) |
| 10 | [UNION — multiple values in a single column](01-Fundamentals/02-string-concat-nuances.md) | Practitioner | String folding / concatenation | [Open Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column) |
| 13 | [Visible error-based SQLi](02-Vulnerability-Types/in-band/error-based.md) | Practitioner | `CAST()` type-conversion leakage | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based) |

---

## Blind (Boolean-Based, Conditional Errors, Time-Based)

| # | Exercise (Internal Write-up) | Difficulty | Core Concept & Reference | PortSwigger Lab Link |
| :--- | :--- | :--- | :--- | :--- |
| 11 | [Conditional responses](02-Vulnerability-Types/blind-inferential/boolean-based.md) | Practitioner | Boolean content-differential oracle | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses) |
| 12 | [Conditional errors](02-Vulnerability-Types/blind-inferential/boolean-based.md) | Practitioner | Induced-error (status-code) oracle | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors) |
| 14 | [Time delays](02-Vulnerability-Types/blind-inferential/time-based.md) | Practitioner | `pg_sleep()` syntax bridging | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays) |
| 15 | [Time delays + information retrieval](03-Advanced-Techniques/stacked-queries-vs-inline.md) | Practitioner | Stacked queries + timing extraction | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval) |

---

## Out-of-Band (OAST)

| # | Exercise (Internal Write-up) | Difficulty | Core Concept & Reference | PortSwigger Lab Link |
| :--- | :--- | :--- | :--- | :--- |
| 16 | [OOB interaction](02-Vulnerability-Types/out-of-band/oast-sqli-dns-http.md) | Practitioner | XXE-triggered DNS callback | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band) |
| 17 | [OOB data exfiltration](02-Vulnerability-Types/out-of-band/oast-sqli-dns-http.md) | Practitioner | Subdomain-encoded data exfil | [Open Lab](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration) |

---

## Filter / WAF Bypass

| # | Exercise (Internal Write-up) | Difficulty | Core Concept & Reference | PortSwigger Lab Link |
| :--- | :--- | :--- | :--- | :--- |
| 18 | [Filter bypass via XML encoding](05-Bypasses-and-WAF/encoding-and-context-bypass.md) | Practitioner | Parser-differential evasion | [Open Lab](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) |

---

**Navigation tip:** Start in the core directories if you want to learn a technique from first principles. Use this index to jump straight into your internal engineering notes or launch the official lab environment for hands-on practice.
