# Filter and WAF Bypass via Encoding and Parser Differentials
 
## The Core Principle: Parser Differential Exploitation
 
Nearly every encoding-based bypass technique exploits the same underlying weakness: **a Web Application Firewall (WAF) and the application's own backend parser do not always agree on what a given byte sequence decodes to, or at what stage of processing it should be decoded.** A WAF inspecting raw request bytes for a blacklisted signature (`UNION`, `SELECT`, `OR 1=1`) can be defeated whenever the backend will eventually decode or transform the payload into that signature **after** the WAF has already inspected and passed it through — because at inspection time, the dangerous string simply wasn't present in the request yet.
 
This is not a flaw unique to any one WAF product — it's a structural consequence of layered request processing, and it generalizes across contexts (URL encoding, XML entity encoding, Unicode normalization, double encoding).
 
## Technique: XML Entity Encoding (Context-Aware Obfuscation)
 
When the injection point is an XML-structured request body (common in SOAP APIs, legacy enterprise integrations, and XML-based stock/inventory check endpoints), the backend's XML parser performs its own decoding pass — distinct from, and occurring *after*, any WAF inspection of the raw request.
 
This creates an exploitable sequence:
 
1. The attacker encodes the malicious SQL payload using standard **XML character entity references** (decimal: `&#85;&#78;&#73;...`, or hexadecimal: `&#x55;&#x4E;&#x49;...`) in place of the literal characters that would normally spell out blacklisted keywords like `UNION` or `SELECT`.
2. The WAF inspects the raw request body. It sees only harmless-looking entity reference sequences — no literal `UNION` or `SELECT` substring exists anywhere in the transmitted bytes — and passes the request through.
3. The backend's XML parser decodes the entity references back into their literal characters **as a normal, expected part of XML processing** (this is not a bug in the XML parser — entity decoding is its designed job).
4. The now-fully-decoded, literal SQL payload is handed to the database exactly as if it had been sent in plaintext.
```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
```
 
The `<@hex_entities>` notation above reflects a Burp Suite extension (Hackvertor) convenience tag used during manual testing to apply the encoding dynamically — the actual payload transmitted on the wire is the fully hex-entity-encoded string, which the backend's XML parser transparently reconstitutes into working SQL before query execution.
 
### Why This Specific Technique Is Durable
 
Signature-based WAF rules are fundamentally reactive — they match known-bad substrings or patterns in the *as-transmitted* request. XML entity encoding doesn't obfuscate the SQL syntax in any way the database cares about; it only obfuscates it **from the WAF's perspective**, by ensuring the dangerous substring is never physically present in the request body the WAF inspects. The backend doesn't need any special handling to "support" this bypass — it's simply doing standard, correct XML parsing, which happens to occur at a processing stage downstream of the WAF.
 
## Generalizing the Technique to Other Encoding Contexts
 
The same parser-differential principle applies wherever a trusted downstream decoding step exists between the WAF and the database:
 
| Context | Encoding Layer Exploited |
|---|---|
| URL query parameters | Percent-encoding (`%55%4E%49%4F%4E` for `UNION`), double percent-encoding (`%2553` decoding to `%53` then to `S`) when an intermediate proxy or application layer decodes once before the WAF re-evaluates |
| JSON string values | Unicode escape sequences (`\u0055\u004E\u0049\u004F\u004E`), decoded by the JSON parser after WAF inspection |
| HTTP headers / cookies | Case variation (`UnIoN SeLeCt`) defeating case-sensitive signature matching; inline comment insertion (`UNI/**/ON SEL/**/ECT`) that most SQL parsers tolerate but naive regex signatures do not |
| Multipart form data | Encoding mismatches between declared and actual charset, exploiting lenient backend charset auto-detection |
 
## Non-Encoding Complementary Bypass Techniques
 
Encoding is one pillar of WAF evasion; it is commonly combined with:
 
- **Inline comment injection**: `UNI/**/ON/**/SEL/**/ECT` — most SQL parsers silently discard inline comments during tokenization, but a naive signature match on the contiguous string `UNION SELECT` will not fire.
- **Case randomization**: `uNiOn SeLeCt` — effective only against case-sensitive signature rules, increasingly rare but still present in legacy WAF configurations.
- **Whitespace substitution**: replacing standard spaces with tabs, newlines, or SQL-valid alternative whitespace (`UNION%0ASELECT`), which some signature rules fail to normalize before matching.
- **Alternative/synonym functions**: substituting a blacklisted function name with a DBMS-specific equivalent that achieves the same effect but isn't on the WAF's signature list (see `04-DBMS-Specific/` for per-DBMS function inventories).
- **String-literal keyword fragmentation**: splitting a blacklisted keyword across concatenated string literals evaluated only at the database layer (`'UNI'||'ON SELECT'` — see `01-Fundamentals/02-string-concat-nuances.md`), functionally identical in principle to the XML-entity technique but implemented via SQL's own concatenation operator rather than a transport-layer encoding.
## Practical Lab Verification
 
- [Lab 18 — SQL injection with filter bypass via XML encoding](../07-PortSwigger-Labs-Writeups/filter-bypass/lab-18-xml-encoding-filter-bypass.md)
 
