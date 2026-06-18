/// Pointer compared against the literal 0 instead of NULL
//# Pointer tested with `== 0` / `!= 0` reads as an integer comparison
//# and hides that the value is a pointer. Use NULL.
//
// Confidence: High
// Options: --no-includes

// is_zero/isnt_zero isomorphisms are disabled so idiomatic truthiness tests
// (`!ptr`, `if (ptr)`) do not match -- only an explicit `== 0` / `!= 0` does.
@r disable is_zero, isnt_zero@
expression *E;
position p;
@@
(
* E@p == 0
|
* E@p != 0
)

@script:python depends on r@
p << r.p;
@@
coccilib.report.print_report(p[0], "pointer compared to 0; use NULL")
