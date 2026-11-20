# What Is SQL Injection: The Root Cause
 
## Definition
 
SQL injection (SQLi) is a vulnerability class arising whenever an application constructs a SQL query by **directly concatenating attacker-influenceable input into the query string**, without a mechanism that structurally separates that input (data) from the query's own syntax (code). The attacker exploits this by crafting input that, once concatenated, is no longer interpreted by the database as inert data — it is interpreted as additional SQL syntax, altering the query's logic, structure, or scope.
 
## The Data/Code Channel Confusion
 
Every SQL query is, at the database engine's parsing stage, a single undifferentiated string until it is tokenized and parsed into an abstract syntax tree. A parameterized/prepared statement keeps user input entirely out of that string — it is passed to the database as a **separate, typed value bound to a placeholder**, after the query's structure has already been parsed and fixed. A vulnerable, concatenated query instead builds the entire string — structure and data together — *before* parsing, meaning user input is parsed as part of the query's own grammar.
 
```sql
-- Safe: the query structure is fixed before 'INPUT' is ever considered
SELECT * FROM products WHERE category = ?   -- 'INPUT' bound separately, never parsed as SQL
 
-- Vulnerable: the query structure and the input are indistinguishable once concatenated
SELECT * FROM products WHERE category = 'INPUT'
```
 
If `INPUT` is `Gifts' OR 1=1--`, the vulnerable version resolves to a different query entirely — the single quote closes the string literal the developer intended to contain only data, and everything after it is parsed as additional SQL grammar.
 
## Why This Is a Structural Problem, Not a Sanitization Problem
 
A common but flawed mental model treats SQLi as "the input wasn't cleaned enough" — implying that sufficiently aggressive blacklisting or escaping of dangerous characters (`'`, `--`, `;`) solves the problem. This framing is unreliable because:
 
- **Context-dependent escaping requirements**: the correct escaping rules differ depending on whether input lands inside a string literal, a numeric literal, an identifier, or a different clause entirely (see `03-Advanced-Techniques/context-analysis.md`) — a single global escaping rule cannot correctly handle every context.
- **Encoding and parser differentials**: even perfectly escaped input at one layer can be re-decoded into dangerous characters by a downstream parser (see `05-Bypasses-and-WAF/`), reintroducing the vulnerability after the escaping step has already run.
- **Second-order reintroduction**: safely escaped input at storage time can be read back and concatenated unsafely into a *different* query later, with no new user input involved at all (see `02-Vulnerability-Types/second-order-sqli.md`).
The only structurally sound remediation is **parameterization** — never constructing the query string by concatenating input, under any circumstance, in any context. This is covered in full in `09-Remediation/prepared-statements-by-language.md`.
 
## Why SQLi Remains High-Impact Despite Being a "Solved" Problem
 
Mature frameworks and ORMs default to parameterized queries, yet SQLi persists as a leading vulnerability class because:
- Raw query construction is still common in reporting/analytics code, legacy integrations, dynamic sorting/filtering logic (`ORDER BY` clauses can't always be parameterized the same way `WHERE` values can), and ORM "raw query" escape hatches.
- Non-obvious entry points (cookies, headers, second-order storage) are frequently under-tested relative to visible form fields.
- A single successful injection can cascade into full database compromise, authentication bypass, or — via stacked queries and OS-level function abuse — remote code execution, making it consistently one of the highest-severity vulnerability classes when found.
## Practical Lab Verification
 
- [Lab 01 — WHERE clause hidden data](../07-PortSwigger-Labs-Writeups/in-band/lab-01-where-clause-hidden-data.md)
- [Lab 02 — Login bypass](../07-PortSwigger-Labs-Writeups/in-band/lab-02-login-bypass.md)
 
