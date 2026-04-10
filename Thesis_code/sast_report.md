# Suggestor Report

## Summary
- Processed CWEs: CWE-89, CWE-79
- Skipped CWEs: None

## CWE-79

### Existing Coverage
The first query (`ReflectedXssQuery`) already uses the standard Python security dataflow model for reflected XSS: it treats typical “user-controlled” web inputs (framework request parameters, headers, body, cookies, etc., as defined in `semmle.python.security.dataflow.ReflectedXssQuery`) as **sources**, and treats common “HTML response emission” operations (writing/returning strings that become HTTP response bodies, templating render calls, etc., as defined by `ReflectedXssFlow`) as **sinks**, while leveraging the library’s notion of **sanitizers** (escaping/encoding routines already modeled in the underlying Reflected XSS flow configuration). The second query is a separate **configuration misuse** check for `jinja2.Environment(...)` / `jinja2.Template(...)` when `autoescape` is omitted or statically `False`, but it does not connect to taint flow; it just flags potentially unsafe template configuration.

### Gap Identified
A common missed XSS pattern is **server-side HTML construction using “safe string” wrappers that disable escaping**, especially **`markupsafe.Markup(...)` / `Markup.format(...)` / `Markup.__html__`-style constructs** that Jinja2 and many Python web stacks treat as “already escaped.” If user input is wrapped into `markupsafe.Markup` (or concatenated into a `Markup` object) before being written to a response or template context, the current reflected-XSS taint tracking often **stops** (value becomes “trusted/safe”) or the sink model assumes it’s safe—causing the query to miss real vulnerabilities where developers incorrectly mark untrusted content as safe.

### Missing Sources
- Flask/Werkzeug: `flask.request.args.get(<name>)` return value (Call expression)
- Flask/Werkzeug: `flask.request.form.get(<name>)` return value (Call expression)
- Werkzeug: `werkzeug.wrappers.request.Request.headers.get(<name>)` return value (Call expression)
- Django: `django.http.HttpRequest.GET.get(<name>)` / `.POST.get(<name>)` return value (Call expression)

### Missing Sinks
- MarkupSafe: `markupsafe.Markup(<value>)` when `<value>` is (or contains) user-controlled data (Call expression)
- MarkupSafe: `markupsafe.Markup.format(*args, **kwargs)` where any formatting argument is user-controlled (Method call)
- MarkupSafe: string concatenation producing `Markup` (e.g., `Markup("<b>") + user + Markup("</b>")`) (Binary `+` expression where one operand is `Markup`)
- Flask: `flask.Response(<body>)` / `make_response(<body>)` where `<body>` is `Markup` built from user input (Call expression)

### Missing Sanitizers
- MarkupSafe: `markupsafe.escape(<value>)` (Call expression) — *should* be treated as a sanitizer/encoder (HTML-escapes)
- MarkupSafe: `flask.escape(<value>)` (Call expression; typically re-export of MarkupSafe escape)
- (Optional, but common) `html.escape(<value>, quote=True)` from stdlib `html` module (Call expression)
- If a `Call` targets `markupsafe.Markup` and `arg0` is not provably a constant and is tainted, then:
- either (A) consider this `Call` a *sink* equivalent to “writing into HTML context without escaping”, OR
- (B) ensure taint *continues through* the resulting `Markup` object into response-writing sinks (do not treat it as sanitized).
- `if Call(func=Attr(Name("markupsafe"), "Markup") OR Name("Markup"), args=[x], keywords=...) and isTainted(x) and not isEscaped(x): report/propagate`
- For `Call(func=Attr(receiver, "format"), receiverType=Markup, args/kwargs contain y)` and any `y` tainted, treat as sink or propagate taint to result.
- For `Call(func=Attr(Name("markupsafe"), "escape") OR Name("escape") OR Attr(Name("flask"), "escape"), args=[x])`, mark output as sanitized (HTML-escaped), allowing the flow to stop or be downgraded.
- For `BinOp(op="+", left=a, right=b)` where either side is `Markup` and the other side is tainted string, propagate taint into the result (do *not* consider the result safe unless the tainted side is passed through `escape()` first).

### Proposed Addition
EXISTING COVERAGE:
The first query (`ReflectedXssQuery`) already uses the standard Python security dataflow model for reflected XSS: it treats typical “user-controlled” web inputs (framework request parameters, headers, body, cookies, etc., as defined in `semmle.python.security.dataflow.ReflectedXssQuery`) as **sources**, and treats common “HTML response emission” operations (writing/returning strings that become HTTP response bodies, templating render calls, etc., as defined by `ReflectedXssFlow`) as **sinks**, while leveraging the library’s notion of **sanitizers** (escaping/encoding routines already modeled in the underlying Reflected XSS flow configuration). The second query is a separate **configuration misuse** check for `jinja2.Environment(...)` / `jinja2.Template(...)` when `autoescape` is omitted or statically `False`, but it does not connect to taint flow; it just flags potentially unsafe template configuration.

GAP IDENTIFIED:
A common missed XSS pattern is **server-side HTML construction using “safe string” wrappers that disable escaping**, especially **`markupsafe.Markup(...)` / `Markup.format(...)` / `Markup.__html__`-style constructs** that Jinja2 and many Python web stacks treat as “already escaped.” If user input is wrapped into `markupsafe.Markup` (or concatenated into a `Markup` object) before being written to a response or template context, the current reflected-XSS taint tracking often **stops** (value becomes “trusted/safe”) or the sink model assumes it’s safe—causing the query to miss real vulnerabilities where developers incorrectly mark untrusted content as safe.

MISSING SOURCES:
- Flask/Werkzeug: `flask.request.args.get(<name>)` return value (Call expression)
- Flask/Werkzeug: `flask.request.form.get(<name>)` return value (Call expression)
- Werkzeug: `werkzeug.wrappers.request.Request.headers.get(<name>)` return value (Call expression)
- Django: `django.http.HttpRequest.GET.get(<name>)` / `.POST.get(<name>)` return value (Call expression)

MISSING SINKS:
- MarkupSafe: `markupsafe.Markup(<value>)` when `<value>` is (or contains) user-controlled data (Call expression)
- MarkupSafe: `markupsafe.Markup.format(*args, **kwargs)` where any formatting argument is user-controlled (Method call)
- MarkupSafe: string concatenation producing `Markup` (e.g., `Markup("<b>") + user + Markup("</b>")`) (Binary `+` expression where one operand is `Markup`)
- Flask: `flask.Response(<body>)` / `make_response(<body>)` where `<body>` is `Markup` built from user input (Call expression)

MISSING SANITIZERS:
- MarkupSafe: `markupsafe.escape(<value>)` (Call expression) — *should* be treated as a sanitizer/encoder (HTML-escapes)
- MarkupSafe: `flask.escape(<value>)` (Call expression; typically re-export of MarkupSafe escape)
- (Optional, but common) `html.escape(<value>, quote=True)` from stdlib `html` module (Call expression)

PROPOSED ADDITION (Python-mapped AST pseudo-code, NOT CodeQL syntax yet):
Add a small set of additional flow modeling rules in the reflected-XSS configuration (not the Jinja2 autoescape check) focusing on MarkupSafe:
1) **Treat “unsafe safe-marking” as a sink (or a taint-propagating hazard):**
   - If a `Call` targets `markupsafe.Markup` and `arg0` is not provably a constant and is tainted, then:
     - either (A) consider this `Call` a *sink* equivalent to “writing into HTML context without escaping”, OR
     - (B) ensure taint *continues through* the resulting `Markup` object into response-writing sinks (do not treat it as sanitized).
   Pseudo-code:
   - `if Call(func=Attr(Name("markupsafe"), "Markup") OR Name("Markup"), args=[x], keywords=...) and isTainted(x) and not isEscaped(x): report/propagate`
2) **Model `Markup.format(...)` as an HTML sink for format arguments:**
   - For `Call(func=Attr(receiver, "format"), receiverType=Markup, args/kwargs contain y)` and any `y` tainted, treat as sink or propagate taint to result.
3) **Model `escape(...)` as sanitizer:**
   - For `Call(func=Attr(Name("markupsafe"), "escape") OR Name("escape") OR Attr(Name("flask"), "escape"), args=[x])`, mark output as sanitized (HTML-escaped), allowing the flow to stop or be downgraded.
4) **Handle `Markup` concatenation propagation:**
   - For `BinOp(op="+", left=a, right=b)` where either side is `Markup` and the other side is tainted string, propagate taint into the result (do *not* consider the result safe unless the tainted side is passed through `escape()` first).

ESTIMATED IMPACT: high

### Estimated Impact
high

### Evidence Files
- cwefixes/src/OFS/Image.py
- cwefixes/reviewboard/reviews/templatetags/reviewtags.py
- cwefixes/django/contrib/admin/widgets.py

## CWE-89

### Existing Coverage
The current query delegates everything to `semmle.python.security.dataflow.SqlInjectionQuery` (via `SqlInjectionFlow::flowPath`), so it already covers the default Python SQL-injection taint model: common untrusted sources (e.g., web-framework request data and CLI/env inputs as modeled by the library), propagation through string-building operations (concatenation/formatting as supported by the library’s taint steps), and sinks mapped in the standard library model (notably DB-API style execution calls such as `cursor.execute(sql, ...)` / `cursor.executemany(sql, ...)` where the SQL string argument is tainted). It also benefits from the library’s built-in barriers/sanitizers for recognized “safe” parameter binding patterns (placeholders in the SQL text with user values passed out-of-band in the parameters argument), insofar as those are modeled in the standard query.

##

### Gap Identified
A frequent miss in practice is SQL execution through **non-DB-API “raw SQL string” entry points** that are outside (or only partially covered by) the default `SqlInjectionQuery` sinks—especially **SQLAlchemy 1.4/2.x** APIs (`Connection.execute(...)`, `Session.execute(...)`) and **pandas** convenience wrappers (`pandas.read_sql(...)`, `pandas.read_sql_query(...)`). These functions accept a SQL string (or “text clause”) and will execute it; when developers build that SQL with f-strings / `%` / `.format` (or via `" ... " + user`), the vulnerability is the same, but the sink may not be recognized by the existing model.

##

### Missing Sources
- **FastAPI/Starlette**: `starlette.requests.Request.query_params.get(name: str, default: Any=None) -> str | None`
- **FastAPI/Starlette**: `starlette.requests.Request.path_params` (e.g., `request.path_params["id"]`)
- **FastAPI/Starlette**: `starlette.requests.Request.headers.get(key: str, default: Any=None) -> str | None`
- **Flask/Werkzeug**: `flask.Request.args.get(key: str, default=None, type=None) -> str | None` (if not already modeled)
- **Django**: `django.http.HttpRequest.GET.get(key: str, default=None) -> str | None` (if not already modeled)

### Missing Sinks
- **SQLAlchemy (Core)**: `sqlalchemy.engine.Connection.execute(statement, parameters=None, **kw)` when `statement` is a `str` (raw SQL) or a `TextClause` created from a tainted string
- **SQLAlchemy (ORM)**: `sqlalchemy.orm.Session.execute(statement, params=None, **kw)` with `statement` as tainted `str` / tainted `TextClause`
- **SQLAlchemy text construction**: `sqlalchemy.text(text: str) -> sqlalchemy.sql.elements.TextClause` when `text` is tainted and the resulting `TextClause` flows into `.execute(...)`
- **pandas**: `pandas.read_sql(sql, con, params=None, **kwargs)` when `sql` is tainted string
- **pandas**: `pandas.read_sql_query(sql, con, params=None, **kwargs)` when `sql` is tainted string

### Missing Sanitizers
- **SQLAlchemy parameterization (TextClause bind params)**: `sqlalchemy.text("... WHERE x=:x").bindparams(x=value)` (treat as barrier when tainted data goes via bindparams/params, not string concatenation)
- **SQLAlchemy execute with separate params dict/tuple**: `Connection.execute(text("... WHERE x=:x"), {"x": user})` / `Session.execute(text("... WHERE x=:x"), {"x": user})` (treat as barrier for the user value if it does *not* flow into the SQL text)
- **pandas parameterization**: `pandas.read_sql_query("... WHERE x = %s", con, params=[user])` (treat as barrier when user only appears in `params`, not inside `sql`)
- Match a `Call` node where:
- callee resolves to attribute `.execute` on an object whose type/module is `sqlalchemy.engine.Connection` or `sqlalchemy.orm.Session` (or conservatively: any `.execute` where the receiver is from module `sqlalchemy`)
- and argument `arg0` (the `statement`) is:
- a `StringLiteral` OR
- an `JoinedStr` (f-string) OR
- a `BinOp(Add)` string concatenation OR
- a `Call` to `format()` / `%` formatting result OR
- a `Call` to `sqlalchemy.text(tainted_string)` (track taint into the `text()` argument and treat the return as a “SQL statement” object)
- Match a `Call` node where callee resolves to:
- `pandas.read_sql(sql, con, params=...)` OR `pandas.read_sql_query(sql, con, params=...)`
- and `sql` argument is tainted (same “constructed string” patterns as above).
- For the above sinks, add a barrier condition: if user-controlled data flows only into the **parameters** position (`params` / `parameters`) and *not* into the SQL text (`statement` / `sql`), then do not report. Concretely:
- Treat flows into `.execute(statement, parameters=TAINTED)` as safe *when* `statement` is not tainted.
- Treat flows into `read_sql*(sql=NOT_TAINTED, params=TAINTED)` as safe.

### Proposed Addition
## EXISTING COVERAGE:
The current query delegates everything to `semmle.python.security.dataflow.SqlInjectionQuery` (via `SqlInjectionFlow::flowPath`), so it already covers the default Python SQL-injection taint model: common untrusted sources (e.g., web-framework request data and CLI/env inputs as modeled by the library), propagation through string-building operations (concatenation/formatting as supported by the library’s taint steps), and sinks mapped in the standard library model (notably DB-API style execution calls such as `cursor.execute(sql, ...)` / `cursor.executemany(sql, ...)` where the SQL string argument is tainted). It also benefits from the library’s built-in barriers/sanitizers for recognized “safe” parameter binding patterns (placeholders in the SQL text with user values passed out-of-band in the parameters argument), insofar as those are modeled in the standard query.

## GAP IDENTIFIED:
A frequent miss in practice is SQL execution through **non-DB-API “raw SQL string” entry points** that are outside (or only partially covered by) the default `SqlInjectionQuery` sinks—especially **SQLAlchemy 1.4/2.x** APIs (`Connection.execute(...)`, `Session.execute(...)`) and **pandas** convenience wrappers (`pandas.read_sql(...)`, `pandas.read_sql_query(...)`). These functions accept a SQL string (or “text clause”) and will execute it; when developers build that SQL with f-strings / `%` / `.format` (or via `" ... " + user`), the vulnerability is the same, but the sink may not be recognized by the existing model.

## MISSING SOURCES:
- **FastAPI/Starlette**: `starlette.requests.Request.query_params.get(name: str, default: Any=None) -> str | None`
- **FastAPI/Starlette**: `starlette.requests.Request.path_params` (e.g., `request.path_params["id"]`)
- **FastAPI/Starlette**: `starlette.requests.Request.headers.get(key: str, default: Any=None) -> str | None`
- **Flask/Werkzeug**: `flask.Request.args.get(key: str, default=None, type=None) -> str | None` (if not already modeled)
- **Django**: `django.http.HttpRequest.GET.get(key: str, default=None) -> str | None` (if not already modeled)

## MISSING SINKS:
- **SQLAlchemy (Core)**: `sqlalchemy.engine.Connection.execute(statement, parameters=None, **kw)` when `statement` is a `str` (raw SQL) or a `TextClause` created from a tainted string
- **SQLAlchemy (ORM)**: `sqlalchemy.orm.Session.execute(statement, params=None, **kw)` with `statement` as tainted `str` / tainted `TextClause`
- **SQLAlchemy text construction**: `sqlalchemy.text(text: str) -> sqlalchemy.sql.elements.TextClause` when `text` is tainted and the resulting `TextClause` flows into `.execute(...)`
- **pandas**: `pandas.read_sql(sql, con, params=None, **kwargs)` when `sql` is tainted string
- **pandas**: `pandas.read_sql_query(sql, con, params=None, **kwargs)` when `sql` is tainted string

## MISSING SANITIZERS:
- **SQLAlchemy parameterization (TextClause bind params)**: `sqlalchemy.text("... WHERE x=:x").bindparams(x=value)` (treat as barrier when tainted data goes via bindparams/params, not string concatenation)
- **SQLAlchemy execute with separate params dict/tuple**: `Connection.execute(text("... WHERE x=:x"), {"x": user})` / `Session.execute(text("... WHERE x=:x"), {"x": user})` (treat as barrier for the user value if it does *not* flow into the SQL text)
- **pandas parameterization**: `pandas.read_sql_query("... WHERE x = %s", con, params=[user])` (treat as barrier when user only appears in `params`, not inside `sql`)

## PROPOSED ADDITION (Python-mapped AST pseudo-code, NOT CodeQL syntax yet):
Add new sink matchers (and related barrier logic) to the existing SQLi flow configuration used by `SqlInjectionQuery`, without rewriting the query:
1. **New sinks for SQLAlchemy**  
   - Match a `Call` node where:
     - callee resolves to attribute `.execute` on an object whose type/module is `sqlalchemy.engine.Connection` or `sqlalchemy.orm.Session` (or conservatively: any `.execute` where the receiver is from module `sqlalchemy`)
     - and argument `arg0` (the `statement`) is:
       - a `StringLiteral` OR
       - an `JoinedStr` (f-string) OR
       - a `BinOp(Add)` string concatenation OR
       - a `Call` to `format()` / `%` formatting result OR
       - a `Call` to `sqlalchemy.text(tainted_string)` (track taint into the `text()` argument and treat the return as a “SQL statement” object)
2. **New sinks for pandas**  
   - Match a `Call` node where callee resolves to:
     - `pandas.read_sql(sql, con, params=...)` OR `pandas.read_sql_query(sql, con, params=...)`
     - and `sql` argument is tainted (same “constructed string” patterns as above).
3. **Barrier/sanitizer refinement for “separate parameters”**  
   - For the above sinks, add a barrier condition: if user-controlled data flows only into the **parameters** position (`params` / `parameters`) and *not* into the SQL text (`statement` / `sql`), then do not report. Concretely:
     - Treat flows into `.execute(statement, parameters=TAINTED)` as safe *when* `statement` is not tainted.
     - Treat flows into `read_sql*(sql=NOT_TAINTED, params=TAINTED)` as safe.

## ESTIMATED IMPACT: high

### Estimated Impact
high

### Evidence Files
- cwefixes/django/contrib/postgres/aggregates/mixins.py
- cwefixes/mod_fun/__init__.py
- cwefixes/auth/controllers/group_controller.py
- cwefixes/auth/controllers/user_controller.py
- cwefixes/redports-trac/redports/model.py
- cwefixes/flair.py