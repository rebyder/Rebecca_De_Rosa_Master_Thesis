/**
 * @name SQL injection (extended: SQLAlchemy execute/text + framework `.get` sources)
 * @description Finds SQL injection vulnerabilities.
 * @kind path-problem
 * @problem.severity warning
 * @id py/sql-injection-extended
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery
import SqlInjectionFlow::PathGraph

/**
 * NOTE:
 * This query is an *extension* of the standard SqlInjectionQuery.
 * The final from/where/select clause below must remain unchanged.
 */

/** Additional sources: request parameter `.get(...)` helpers (FastAPI/Starlette + Flask). */
private class StarletteRequestGetSource extends SqlInjectionFlow::Source {
  StarletteRequestGetSource() {
    exists(API::Call c |
      (
        c = API::moduleImport("starlette.requests")
              .getMember("Request")
              .getMember("query_params")
              .getMember("get")
              .getACall()
        or
        c = API::moduleImport("starlette.requests")
              .getMember("Request")
              .getMember("path_params")
              .getMember("get")
              .getACall()
      ) and
      this.asExpr() = c
    )
  }
}

private class FastapiRequestGetSource extends SqlInjectionFlow::Source {
  FastapiRequestGetSource() {
    exists(API::Call c |
      (
        c = API::moduleImport("fastapi")
              .getMember("Request")
              .getMember("query_params")
              .getMember("get")
              .getACall()
        or
        c = API::moduleImport("fastapi")
              .getMember("Request")
              .getMember("path_params")
              .getMember("get")
              .getACall()
      ) and
      this.asExpr() = c
    )
  }
}

private class FlaskRequestGetSource extends SqlInjectionFlow::Source {
  FlaskRequestGetSource() {
    exists(API::Call c |
      (
        c = API::moduleImport("flask")
              .getMember("request")
              .getMember("args")
              .getMember("get")
              .getACall()
        or
        c = API::moduleImport("flask")
              .getMember("request")
              .getMember("form")
              .getMember("get")
              .getACall()
      ) and
      this.asExpr() = c
    )
  }
}

/** Additional SQLAlchemy sinks: textual SQL execution surfaces. */
private class SqlAlchemyExecuteArg0Sink extends SqlInjectionFlow::Sink {
  SqlAlchemyExecuteArg0Sink() {
    exists(API::Call c |
      (
        c = API::moduleImport("sqlalchemy.engine")
              .getMember("Connection")
              .getMember("execute")
              .getACall()
        or
        c = API::moduleImport("sqlalchemy.orm")
              .getMember("Session")
              .getMember("execute")
              .getACall()
      ) and
      this.asExpr() = c.getArgument(0)
    )
  }
}

/** Capture direct construction of textual SQL via sqlalchemy.text(sqltext). */
private class SqlAlchemyTextArg0Sink extends SqlInjectionFlow::Sink {
  SqlAlchemyTextArg0Sink() {
    exists(API::Call c |
      c = API::moduleImport("sqlalchemy")
            .getMember("text")
            .getACall() and
      this.asExpr() = c.getArgument(0)
    )
  }
}

/**
 * Additional sanitizers for SQLAlchemy parameter binding.
 *
 * - If user input is passed as separate parameters (2nd argument), it should not be treated as
 *   affecting SQL syntax.
 * - TextClause.bindparams(...) binds parameters safely.
 */
private class SqlAlchemyExecuteParamsSanitizer extends SqlInjectionFlow::Sanitizer {
  SqlAlchemyExecuteParamsSanitizer() {
    exists(API::Call c |
      (
        c = API::moduleImport("sqlalchemy.engine")
              .getMember("Connection")
              .getMember("execute")
              .getACall()
        or
        c = API::moduleImport("sqlalchemy.orm")
              .getMember("Session")
              .getMember("execute")
              .getACall()
      ) and
      // sanitize the parameter object (not the statement)
      this.asExpr() = c.getArgument(1)
    )
  }
}

private class SqlAlchemyBindParamsSanitizer extends SqlInjectionFlow::Sanitizer {
  SqlAlchemyBindParamsSanitizer() {
    exists(API::Call c |
      c = API::moduleImport("sqlalchemy.sql")
            .getMember("elements")
            .getMember("TextClause")
            .getMember("bindparams")
            .getACall() and
      this.asExpr() = c
    )
  }
}

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Possible SQL injection vulnerability."