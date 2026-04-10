/**
 * @name Reflected XSS (extended: Jinja2 rendering + MarkupSafe escaping)
 * @description Finds reflected cross-site scripting vulnerabilities with additional coverage for Jinja2 template rendering APIs.
 * @kind path-problem
 * @problem.severity warning
 * @id py/reflective-xss-extended
 * @tags security
 *       external/cwe/cwe-079
 */

import python
import semmle.python.security.dataflow.ReflectedXssQuery
import ReflectedXssFlow::PathGraph

/**
 * Additional sinks for Jinja2 rendering.
 */
private class Jinja2RenderingSink extends ReflectedXssFlow::Sink {
  Jinja2RenderingSink() {
    // jinja2.Template(...).render(...)
    this.asExpr() =
      API::moduleImport("jinja2")
        .getMember("Template")
        .getACall()
        .getMember("render")
        .getACall()
        .getArgument(0)

    or

    // jinja2.Template(...).generate(...)
    this.asExpr() =
      API::moduleImport("jinja2")
        .getMember("Template")
        .getACall()
        .getMember("generate")
        .getACall()
        .getArgument(0)

    or

    // jinja2.Template(...).stream(...)
    this.asExpr() =
      API::moduleImport("jinja2")
        .getMember("Template")
        .getACall()
        .getMember("stream")
        .getACall()
        .getArgument(0)

    or

    // jinja2.Environment(...).get_template(...).render(...)
    this.asExpr() =
      API::moduleImport("jinja2")
        .getMember("Environment")
        .getACall()
        .getMember("get_template")
        .getACall()
        .getMember("render")
        .getACall()
        .getArgument(0)
  }
}

/**
 * Additional sanitizers for MarkupSafe/Jinja2 escaping.
 */
private class MarkupSafeEscapeSanitizer extends ReflectedXssFlow::Sanitizer {
  MarkupSafeEscapeSanitizer() {
    // markupsafe.escape(x)
    this.asExpr() =
      API::moduleImport("markupsafe")
        .getMember("escape")
        .getACall()

    or

    // jinja2.escape(x)
    this.asExpr() =
      API::moduleImport("jinja2")
        .getMember("escape")
        .getACall()

    or

    // markupsafe.Markup.escape(x)
    this.asExpr() =
      API::moduleImport("markupsafe")
        .getMember("Markup")
        .getMember("escape")
        .getACall()
  }
}

/**
 * Additional sources for common request parameter `.get` patterns.
 */
private class WebRequestGetSource extends ReflectedXssFlow::Source {
  WebRequestGetSource() {
    // flask.request.args.get(...)
    this.asExpr() =
      API::moduleImport("flask")
        .getMember("request")
        .getMember("args")
        .getMember("get")
        .getACall()

    or

    // flask.request.form.get(...)
    this.asExpr() =
      API::moduleImport("flask")
        .getMember("request")
        .getMember("form")
        .getMember("get")
        .getACall()

    or

    // flask.request.values.get(...)
    this.asExpr() =
      API::moduleImport("flask")
        .getMember("request")
        .getMember("values")
        .getMember("get")
        .getACall()

    or

    // flask.request.cookies.get(...)
    this.asExpr() =
      API::moduleImport("flask")
        .getMember("request")
        .getMember("cookies")
        .getMember("get")
        .getACall()

    or

    // django.http.request.HttpRequest.GET.get(...)
    this.asExpr() =
      API::moduleImport("django.http")
        .getMember("HttpRequest")
        .getMember("GET")
        .getMember("get")
        .getACall()

    or

    // django.http.request.HttpRequest.POST.get(...)
    this.asExpr() =
      API::moduleImport("django.http")
        .getMember("HttpRequest")
        .getMember("POST")
        .getMember("get")
        .getACall()
  }
}

from ReflectedXssFlow::PathNode source, ReflectedXssFlow::PathNode sink
where ReflectedXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Reflected XSS vulnerability."