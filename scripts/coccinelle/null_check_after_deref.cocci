/// Pointer dereferenced before it is checked for NULL.
//# If a NULL check is worth doing, it has to come before the first dereference
//# Checking afterwards is too late and signals a logic error.
//
// Confidence: Moderate
// Options: --no-includes

@r@
expression E, E2;
identifier fld;
position p;
@@
* E->fld
  ... when != E = E2
      when != E != NULL
      when != E == NULL
* if (E@p == NULL) { ... }

@script:python depends on r@
p << r.p;
@@
coccilib.report.print_report(p[0], "NULL check after the pointer was already dereferenced")
