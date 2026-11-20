# Reconnaissance & Identifying Entry Points
 
## The First Principle: Any User-Controlled Input Is a Candidate
 
A disproportionate amount of SQLi hunting failure comes not from a lack of exploitation skill, but from **never testing the right injection point in the first place** because it wasn't visually obvious. Treat every piece of attacker-influenceable data entering the application — regardless of whether it's ever rendered back to the user — as a candidate injection point until proven otherwise.
 
## Primary Entry Point Categories
 
### 1. URL Query Parameters and Path Segments
The most commonly tested (and most commonly already-defended) category. Includes standard `?param=value` query strings, but also **path-based parameters** in REST-style routing (`/products/{category}/`) and parameters embedded in referrer/redirect chains.
 
### 2. POST Body Parameters
Standard form fields, JSON request bodies, and multipart form data. Particularly high-value on **authentication endpoints** (login, password reset, account recovery) where successful injection yields immediate, severe impact (see login-bypass patterns).
 
### 3. HTTP Cookies
Cookies used for session tracking, analytics, A/B test bucketing, or user preference persistence (e.g., a `TrackingId` or similar identifier) are frequently concatenated directly into logging or analytics queries **without the same input validation rigor applied to user-facing form fields** — developers often implicitly trust values the *application itself* set, forgetting that cookies are fully attacker-controlled and trivially modified client-side. This makes cookies a disproportionately high-yield, under-tested target relative to how often they're actually audited by developers or automated scanners.
 
### 4. HTTP Headers
- **`X-Forwarded-For` / `X-Real-IP` / `Client-IP`**: frequently logged directly into audit or analytics tables for IP-based tracking, geolocation lookups, or rate-limiting logic — a classic second-order injection vector (see below) when the logged value is later read back into another query.
- **`User-Agent` / `Referer`**: logged for analytics purposes in a similar pattern; historically a common vector in CMS and forum software injection disclosures.
- **Custom application headers**: any bespoke header used for internal routing, feature flags, or multi-tenant identification deserves the same scrutiny as a query parameter.
### 5. Second-Order Injection Points
Data submitted in one request (and safely stored, perhaps even properly escaped at storage time) can become an injection vector when **later read back and concatenated unsafely into a different query** — a username containing a crafted payload at registration time might be perfectly safe when stored, but trigger injection when a separate administrative report query later concatenates that username into a raw SQL string without equivalent sanitization. Always test whether stored values (profile fields, display names, previously submitted free-text) resurface in administrative panels, reports, exports, or other secondary query contexts.
 
## Systematic Reconnaissance Workflow
 
1. **Map every distinct request parameter** across the entire application surface — proxy-capture an authenticated crawl and extract every unique parameter name from URLs, bodies, cookies, and headers, not just the ones visibly tied to search/filter functionality.
2. **Prioritize by data sensitivity and query likelihood**: parameters tied to lookups, filters, sorting, account identifiers, and tracking/analytics functionality are statistically far more likely to feed directly into a raw SQL query than purely cosmetic/UI-state parameters.
3. **Test every entry point independently** — a parameter that appears unexploitable in isolation may still be concatenated into a vulnerable query elsewhere in the request handling chain; absence of an obvious reflection or behavioral change is not proof of safety, only grounds for escalating to blind/inferential techniques.
4. **Don't stop at the first confirmed injection point** — a single endpoint may have multiple independently injectable parameters, and the easiest-to-exploit one (e.g., supporting UNION) may not be the same one that yields the highest-value data (e.g., a second parameter with access to a different table scope).
## Transition to Detection
 
Once candidate entry points are enumerated, proceed to systematic probing as detailed in `01-detection-phase.md` — syntax-breaking, boolean differential testing, and conditional error induction, in that order of increasing invasiveness and decreasing signal reliability.
 
