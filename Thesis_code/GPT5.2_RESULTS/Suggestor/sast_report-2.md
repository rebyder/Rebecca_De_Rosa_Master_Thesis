# Suggestor Report

## Summary
- Processed CWEs: CWE-89, CWE-78, CWE-79
- Skipped CWEs: None

## CWE-78

### Existing Coverage
The existing queries rely on the standard `semmle.python.security.dataflow.CommandInjectionQuery` and `UnsafeShellCommandConstructionQuery` configurations, which already model common *external* sources (typical web-request and environment-derived user input modeled by the library), common command-execution sinks (`os.system`, `subprocess.*` variants, and other command-launching APIs modeled by the standard “command injection” framework), and known mitigations/sanitizers that the library treats as making data safe for shell usage (for example, patterns where a command is executed without invoking a shell, or where arguments are passed as a list rather than a shell string—depending on how the library models it). They also include path rendering via `PathGraph` and report flows from modeled sources to modeled sinks and from constructed command strings to later execution.

### Gap Identified
A frequent missed pattern for CWE-78 in Python is **command execution via `subprocess` APIs where `shell=True` is supplied indirectly** (e.g., through a `**kwargs` dict, a variable passed as `shell=flag`, or a wrapper function that forwards keyword arguments). Many CodeQL models catch direct `subprocess.run(user, shell=True)` style sinks, but can miss cases where the `shell=True` condition is not a literal at the call site or where the call is made through `Popen.__init__`/`Popen` wrappers. As a result, attacker-controlled strings reaching `subprocess.run(..., **opts)` (with `opts={"shell": True}`) or `Popen(cmd, **opts)` may not be recognized as a shell-command execution sink, and therefore no flow is reported.

### Missing Sources
- (No new sources proposed; leverage existing external-input source modeling in `CommandInjectionQuery` / `UnsafeShellCommandConstructionQuery`.)

### Missing Sinks
- `subprocess.run(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.Popen(args, *, shell=True, ...)` (constructor call) when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.call(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.check_output(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.check_call(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean

### Missing Sanitizers
- `subprocess.*(args=<list/tuple of args>, shell=False)` (or absence of `shell=True`) as an explicit “safe execution” pattern when arguments are not a shell string
- Use of `shlex.quote(s: str) -> str` applied to *every* untrusted fragment before concatenation into a shell string (recognize as a partial sanitizer for shell-string contexts)

### Proposed Addition
EXISTING COVERAGE:
The existing queries rely on the standard `semmle.python.security.dataflow.CommandInjectionQuery` and `UnsafeShellCommandConstructionQuery` configurations, which already model common *external* sources (typical web-request and environment-derived user input modeled by the library), common command-execution sinks (`os.system`, `subprocess.*` variants, and other command-launching APIs modeled by the standard “command injection” framework), and known mitigations/sanitizers that the library treats as making data safe for shell usage (for example, patterns where a command is executed without invoking a shell, or where arguments are passed as a list rather than a shell string—depending on how the library models it). They also include path rendering via `PathGraph` and report flows from modeled sources to modeled sinks and from constructed command strings to later execution.

GAP IDENTIFIED:
A frequent missed pattern for CWE-78 in Python is **command execution via `subprocess` APIs where `shell=True` is supplied indirectly** (e.g., through a `**kwargs` dict, a variable passed as `shell=flag`, or a wrapper function that forwards keyword arguments). Many CodeQL models catch direct `subprocess.run(user, shell=True)` style sinks, but can miss cases where the `shell=True` condition is not a literal at the call site or where the call is made through `Popen.__init__`/`Popen` wrappers. As a result, attacker-controlled strings reaching `subprocess.run(..., **opts)` (with `opts={"shell": True}`) or `Popen(cmd, **opts)` may not be recognized as a shell-command execution sink, and therefore no flow is reported.

MISSING SOURCES:
- (No new sources proposed; leverage existing external-input source modeling in `CommandInjectionQuery` / `UnsafeShellCommandConstructionQuery`.)

MISSING SINKS:
- `subprocess.run(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.Popen(args, *, shell=True, ...)` (constructor call) when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.call(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.check_output(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean
- `subprocess.check_call(args, *, shell=True, ...)` when `shell=True` is provided via `**kwargs` (dict expansion) or a non-literal boolean

MISSING SANITIZERS:
- `subprocess.*(args=<list/tuple of args>, shell=False)` (or absence of `shell=True`) as an explicit “safe execution” pattern when arguments are not a shell string
- Use of `shlex.quote(s: str) -> str` applied to *every* untrusted fragment before concatenation into a shell string (recognize as a partial sanitizer for shell-string contexts)

PROPOSED ADDITION (CodeQL QL predicates — use the same imports and class hierarchy as the existing query):
```ql
import python
import semmle.python.security.dataflow.CommandInjectionQuery
import CommandInjectionFlow::PathGraph

/**
 * Adds sinks for subprocess invocations where shell=True is supplied indirectly
 * (for example via **kwargs dict expansion or non-literal values).
 */
private class IndirectShellTrueSubprocessSink extends CommandInjectionFlow::Sink {
  IndirectShellTrueSubprocessSink() { this = any(Call c | isIndirectShellTrueSubprocessCall(c)).asSink() }

  private predicate isIndirectShellTrueSubprocessCall(Call c) {
    exists(AttributeAccess callee |
      callee = c.getCallee() and
      callee.getQualifier() instanceof Name and
      callee.getQualifier().(Name).getId() = "subprocess" and
      callee.getAttributeName() in ["run", "call", "check_call", "check_output", "Popen"]
    )
    and hasShellTrueViaKwargsOrNonLiteral(c)
  }

  /**
   * Matches cases where shell=True is not a simple literal at the callsite,
   * including `**opts` where opts contains {"shell": True}, or `shell=flag`.
   */
  private predicate hasShellTrueViaKwargsOrNonLiteral(Call c) {
    // Case 1: explicit keyword but value is not the literal False (treat unknown as potentially True).
    exists(KeywordArgument ka |
      ka = c.getKeywordArgument("shell") and
      not ka.getValue() instanceof False
    )
    or
    // Case 2: dict expansion **kwargs (keyword splat) present: treat as potentially enabling shell.
    // (Conservative: if **kwargs exists, and no explicit shell=False, assume may be shell=True.)
    exists(StarStarArgument ssa |
      ssa = c.getStarStarArgument()
    )
    and not exists(KeywordArgument ka2 |
      ka2 = c.getKeywordArgument("shell") and ka2.getValue() instanceof False
    )
  }
}

/**
 * Optional: recognize shlex.quote as a sanitizer for shell-string contexts.
 * (This is conservative and should only be used if the base config doesn’t already model it.)
 */
private class ShlexQuoteSanitizer extends CommandInjectionFlow::Sanitizer {
  override predicate isSanitizer(Node n) {
    exists(Call c, AttributeAccess callee |
      c = n.asExpr() and
      callee = c.getCallee() and
      callee.getQualifier() instanceof Name and
      callee.getQualifier().(Name).getId() = "shlex" and
      callee.getAttributeName() = "quote"
    )
  }
}
```

ESTIMATED IMPACT: medium

### Estimated Impact
medium

### Evidence Files
- data/src/lib/Bcfg2/Server/Plugins/Trigger.py
- data/Data/views.py
- data/web/reNgine/common_func.py
- data/IPython/utils/terminal.py
- data/endpoints/lollms_advanced.py
- data/autogpts/autogpt/autogpt/commands/execute_code.py

## CWE-89

### Existing Coverage
The existing query delegates everything to `semmle.python.security.dataflow.SqlInjectionQuery` and reports paths via `SqlInjectionFlow::flowPath`. That standard library model typically covers common user-controlled sources (web framework request inputs, environment/CLI, etc.), common SQL construction and execution sinks (DB-API `cursor.execute/executemany`, some ORM raw-execution APIs), and basic sanitization/guard patterns where parameters are passed separately (parameterized queries) rather than concatenated into SQL text.

### Gap Identified
A frequent miss in Python SQLi models is *non-DB-API* execution surfaces—especially SQLAlchemy’s “textual SQL” execution path—where the SQL string is supplied to `Connection.execute(...)` / `Session.execute(...)` as a `str` or `sqlalchemy.sql.elements.TextClause` created by `sqlalchemy.text(...)`. If the model only recognizes classic `cursor.execute(query, params)` style sinks, it can miss SQLAlchemy code that builds SQL dynamically (f-strings/concat) and then executes via SQLAlchemy’s `execute`, which is still vulnerable unless parameters are properly bound.

### Missing Sources
- FastAPI / Starlette: `starlette.requests.Request.query_params.get(...)` result
- FastAPI / Starlette: `starlette.requests.Request.path_params.get(...)` result
- Flask: `flask.Request.args.get(...)` result
- Flask: `flask.Request.form.get(...)` result

### Missing Sinks
- SQLAlchemy: `sqlalchemy.engine.Connection.execute(statement, parameters=None, /, **kw)` when `statement` is a `str` or `TextClause` derived from user-controlled data
- SQLAlchemy ORM: `sqlalchemy.orm.Session.execute(statement, params=None, /, **kw)` when `statement` is a `str` or `TextClause` derived from user-controlled data
- SQLAlchemy: `sqlalchemy.sql.expression.text(sqltext)` when `sqltext` is user-controlled and the resulting `TextClause` flows to `.execute(...)`

### Missing Sanitizers
- SQLAlchemy: parameter binding via `sqlalchemy.text("... WHERE x=:x")` **with** bound parameters passed separately to `execute(..., {"x": value})`
- SQLAlchemy: `TextClause.bindparams(...)` used to bind parameters (as opposed to formatting values into SQL text)

### Proposed Addition
EXISTING COVERAGE:
The existing query delegates everything to `semmle.python.security.dataflow.SqlInjectionQuery` and reports paths via `SqlInjectionFlow::flowPath`. That standard library model typically covers common user-controlled sources (web framework request inputs, environment/CLI, etc.), common SQL construction and execution sinks (DB-API `cursor.execute/executemany`, some ORM raw-execution APIs), and basic sanitization/guard patterns where parameters are passed separately (parameterized queries) rather than concatenated into SQL text.

GAP IDENTIFIED:
A frequent miss in Python SQLi models is *non-DB-API* execution surfaces—especially SQLAlchemy’s “textual SQL” execution path—where the SQL string is supplied to `Connection.execute(...)` / `Session.execute(...)` as a `str` or `sqlalchemy.sql.elements.TextClause` created by `sqlalchemy.text(...)`. If the model only recognizes classic `cursor.execute(query, params)` style sinks, it can miss SQLAlchemy code that builds SQL dynamically (f-strings/concat) and then executes via SQLAlchemy’s `execute`, which is still vulnerable unless parameters are properly bound.

MISSING SOURCES:
- FastAPI / Starlette: `starlette.requests.Request.query_params.get(...)` result
- FastAPI / Starlette: `starlette.requests.Request.path_params.get(...)` result
- Flask: `flask.Request.args.get(...)` result
- Flask: `flask.Request.form.get(...)` result

MISSING SINKS:
- SQLAlchemy: `sqlalchemy.engine.Connection.execute(statement, parameters=None, /, **kw)` when `statement` is a `str` or `TextClause` derived from user-controlled data
- SQLAlchemy ORM: `sqlalchemy.orm.Session.execute(statement, params=None, /, **kw)` when `statement` is a `str` or `TextClause` derived from user-controlled data
- SQLAlchemy: `sqlalchemy.sql.expression.text(sqltext)` when `sqltext` is user-controlled and the resulting `TextClause` flows to `.execute(...)`

MISSING SANITIZERS:
- SQLAlchemy: parameter binding via `sqlalchemy.text("... WHERE x=:x")` **with** bound parameters passed separately to `execute(..., {"x": value})`
- SQLAlchemy: `TextClause.bindparams(...)` used to bind parameters (as opposed to formatting values into SQL text)

PROPOSED ADDITION (CodeQL QL predicates — use the same imports and class hierarchy as the existing query):
```ql
import python
import semmle.python.security.dataflow.SqlInjectionQuery
import SqlInjectionFlow::PathGraph

/**
 * Add SQLAlchemy textual execution sinks that may not be covered by the default model.
 */
private class SqlAlchemyExecuteSink extends SqlInjectionFlow::SinkNode {
  SqlAlchemyExecuteSink() {
    exists(Call c |
      this.asNode() = c and
      (
        // connection.execute(<statement>, ...)
        c.getCallee() instanceof Attribute and
        c.getCallee().(Attribute).getAttr() = "execute"
      ) and
      // We care about the first positional argument: the SQL/text clause.
      this.getNode() = c.getArg(0)
    )
  }
}

/**
 * Add SQLAlchemy text(<sql>) constructor as an additional sink-like step:
 * if user input reaches text(...), it becomes a TextClause that is then executed.
 * (Depending on existing models, this may be better as an additional sink or as an additional
 * flow step; here we add it as a sink to ensure visibility.)
 */
private class SqlAlchemyTextSink extends SqlInjectionFlow::SinkNode {
  SqlAlchemyTextSink() {
    exists(Call c |
      this.asNode() = c and
      c.getCallee() instanceof Name and
      c.getCallee().(Name).getId() = "text" and
      // SQL string argument to sqlalchemy.text(sqltext)
      this.getNode() = c.getArg(0)
    )
  }
}
```

ESTIMATED IMPACT: medium

### Estimated Impact
medium

### Evidence Files
- data/django/contrib/postgres/aggregates/general.py
- data/mod_fun/__init__.py
- data/auth/controllers/group_controller.py
- data/auth/controllers/user_controller.py
- data/app.py
- data/redports-trac/redports/model.py
- data/flair.py

## CWE-79

### Existing Coverage
The existing `py/reflective-xss` query relies on `semmle.python.security.dataflow.ReflectedXssQuery` and `ReflectedXssFlow::flowPath`, which already models common “user-controlled input” sources (typical web framework request parameters) flowing to HTML response sinks (typical response/body writers) with a set of known sanitizers/encoders recognized by the standard library. In addition, the separate `py/jinja2/autoescape-false` query flags creation of `jinja2.Environment(...)` or `jinja2.Template(...)` where `autoescape` is missing or explicitly `False` (when passed as a literal), but it does not connect that configuration to an actual dataflow from user input to rendering.

### Gap Identified
The main gap is missing coverage for the common Jinja2 rendering sinks used in real applications—especially `Template.render(**kwargs)` / `Environment.get_template(...).render(...)`—as XSS sinks in the reflected-XSS taint model. As a result, when untrusted request data is passed into Jinja rendering (particularly in projects that disable autoescaping globally or per-template), the flow may not be reported because the “render” call is not treated as an HTML output sink by `ReflectedXssQuery`’s default sink set.

### Missing Sources
- Flask/Werkzeug: `flask.request.args.get(...)` (Call to `ImmutableMultiDict.get`)
- Flask/Werkzeug: `flask.request.form.get(...)` (Call to `ImmutableMultiDict.get`)
- Flask/Werkzeug: `flask.request.values.get(...)` (Call to `CombinedMultiDict.get`)
- Flask/Werkzeug: `flask.request.cookies.get(...)` (Call to `ImmutableMultiDict.get`)
- Django: `django.http.HttpRequest.GET.get(...)` (Call to `QueryDict.get`)
- Django: `django.http.HttpRequest.POST.get(...)` (Call to `QueryDict.get`)

### Missing Sinks
- Jinja2: `jinja2.Template.render(*args, **kwargs)` returning HTML/XML string used as response content
- Jinja2: `jinja2.Environment.get_template(name).render(*args, **kwargs)` (via returned `Template`)
- Jinja2: `jinja2.Template.generate(*args, **kwargs)` / `jinja2.Template.stream(*args, **kwargs)` (streamed output used in responses)

### Missing Sanitizers
- MarkupSafe: `markupsafe.escape(s: str) -> Markup` (encoding HTML special characters)
- MarkupSafe: `markupsafe.Markup.escape(s: str) -> Markup`
- Jinja2: `jinja2.escape(s)` (in some versions exports MarkupSafe escape), when used to encode untrusted data before rendering
- MarkupSafe: `markupsafe.Markup(s)` ONLY when the input is already trusted/escaped (treat as a sanitizer/taint barrier for false positives where developers deliberately mark safe content)

### Proposed Addition
EXISTING COVERAGE:
The existing `py/reflective-xss` query relies on `semmle.python.security.dataflow.ReflectedXssQuery` and `ReflectedXssFlow::flowPath`, which already models common “user-controlled input” sources (typical web framework request parameters) flowing to HTML response sinks (typical response/body writers) with a set of known sanitizers/encoders recognized by the standard library. In addition, the separate `py/jinja2/autoescape-false` query flags creation of `jinja2.Environment(...)` or `jinja2.Template(...)` where `autoescape` is missing or explicitly `False` (when passed as a literal), but it does not connect that configuration to an actual dataflow from user input to rendering.

GAP IDENTIFIED:
The main gap is missing coverage for the common Jinja2 rendering sinks used in real applications—especially `Template.render(**kwargs)` / `Environment.get_template(...).render(...)`—as XSS sinks in the reflected-XSS taint model. As a result, when untrusted request data is passed into Jinja rendering (particularly in projects that disable autoescaping globally or per-template), the flow may not be reported because the “render” call is not treated as an HTML output sink by `ReflectedXssQuery`’s default sink set.

MISSING SOURCES:
- Flask/Werkzeug: `flask.request.args.get(...)` (Call to `ImmutableMultiDict.get`)
- Flask/Werkzeug: `flask.request.form.get(...)` (Call to `ImmutableMultiDict.get`)
- Flask/Werkzeug: `flask.request.values.get(...)` (Call to `CombinedMultiDict.get`)
- Flask/Werkzeug: `flask.request.cookies.get(...)` (Call to `ImmutableMultiDict.get`)
- Django: `django.http.HttpRequest.GET.get(...)` (Call to `QueryDict.get`)
- Django: `django.http.HttpRequest.POST.get(...)` (Call to `QueryDict.get`)

MISSING SINKS:
- Jinja2: `jinja2.Template.render(*args, **kwargs)` returning HTML/XML string used as response content
- Jinja2: `jinja2.Environment.get_template(name).render(*args, **kwargs)` (via returned `Template`)
- Jinja2: `jinja2.Template.generate(*args, **kwargs)` / `jinja2.Template.stream(*args, **kwargs)` (streamed output used in responses)

MISSING SANITIZERS:
- MarkupSafe: `markupsafe.escape(s: str) -> Markup` (encoding HTML special characters)
- MarkupSafe: `markupsafe.Markup.escape(s: str) -> Markup`
- Jinja2: `jinja2.escape(s)` (in some versions exports MarkupSafe escape), when used to encode untrusted data before rendering
- MarkupSafe: `markupsafe.Markup(s)` ONLY when the input is already trusted/escaped (treat as a sanitizer/taint barrier for false positives where developers deliberately mark safe content)

PROPOSED ADDITION (CodeQL QL predicates — use the same imports and class hierarchy as the existing query):
```ql
import python
import semmle.python.security.dataflow.ReflectedXssQuery
import ReflectedXssFlow::PathGraph

/**
 * Add Jinja2 rendering as an HTML sink for reflected-XSS.
 * This is intentionally narrow: it only targets template rendering entrypoints.
 */
private predicate isJinja2RenderCall(CallNode call) {
  exists(API::Node tmpl |
    // jinja2.Template.render(...)
    tmpl = API::moduleImport("jinja2").getMember("Template") and
    call = tmpl.getMember("render").getACall()
  )
  or
  exists(API::Node env |
    // jinja2.Environment.get_template(...).render(...)
    // Model as: Environment.get_template(...) returns a Template, then .render is invoked.
    // We match the .render call and require the receiver to be a call to get_template.
    env = API::moduleImport("jinja2").getMember("Environment") and
    exists(CallNode getT |
      getT = env.getMember("get_template").getACall() and
      call.getReceiver() = getT
    ) and
    call.getCalleeName() = "render"
}

/**
 * New sink node: anything flowing into Template.render parameters is treated as
 * potentially reflected into HTML output.
 */
class Jinja2RenderSink extends ReflectedXssFlow::SinkNode {
  Jinja2RenderSink() { this.asCfgNode() instanceof CallNode }

  override predicate isSinkNode(DataFlow::Node n) {
    exists(CallNode call |
      call = n.asCfgNode().(CallNode) and
      isJinja2RenderCall(call) and
      // Any user-controlled value passed into render context can become output.
      // (kwargs and positional args are both accepted by Jinja2)
      (
        exists(Expr a | a = call.getArg(_) and n.asExpr() = a)
        or
        exists(Expr kw | kw = call.getKeywordArg(_) and n.asExpr() = kw)
      )
    )
  }
}

/**
 * Add MarkupSafe escaping as a sanitizer/taint barrier.
 */
class MarkupSafeEscapeSanitizer extends ReflectedXssFlow::SanitizerNode {
  override predicate isSanitizerNode(DataFlow::Node n) {
    exists(CallNode call |
      call = n.asCfgNode().(CallNode) and
      (
        call = API::moduleImport("markupsafe").getMember("escape").getACall()
        or
        call = API::moduleImport("markupsafe").getMember("Markup").getMember("escape").getACall()
        or
        call = API::moduleImport("jinja2").getMember("escape").getACall()
      )
    )
  }
}
```

ESTIMATED IMPACT: high

### Estimated Impact
high

### Evidence Files
- data/src/OFS/Image.py
- data/reviewboard/reviews/templatetags/reviewtags.py
- data/django/contrib/admin/widgets.py