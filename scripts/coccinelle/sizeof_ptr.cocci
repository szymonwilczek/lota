/// memset/memcpy length given as sizeof(ptr) instead of sizeof(*ptr).
//# Sizing a buffer operation by sizeof(pointer) copies/clears only the
//# pointer width, not the pointed-to object -- almost always a bug.
//# Metavariable is typed as a pointer so genuine arrays (where sizeof is
//# correct) do not match.
//
// Confidence: High
// Options: --no-includes

@r@
expression *ptr;
position p;
@@
(
* memset(ptr, ..., sizeof(ptr))@p
|
* memcpy(ptr, ..., sizeof(ptr))@p
|
* memcpy(..., ptr, sizeof(ptr))@p
)

@script:python depends on r@
p << r.p;
@@
coccilib.report.print_report(p[0], "sizeof(pointer) as a buffer length; did you mean sizeof(*ptr)?")
