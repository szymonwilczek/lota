/// malloc() immediately followed by memset(0) over the same size.
//# malloc + zero-fill of the whole allocation is exactly calloc(), which
//# also guards the size multiplication against overflow.
//
// Confidence: Moderate
// Options: --no-includes

@r@
expression x, size;
position p;
@@
* x = malloc(size);
  ... when != x
* memset(x, 0, size)@p;

@script:python depends on r@
p << r.p;
@@
coccilib.report.print_report(p[0], "malloc + memset(0) over the same size; prefer calloc()")
