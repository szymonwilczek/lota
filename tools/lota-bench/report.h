/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench report - what a session found, in text
 */

#ifndef LOTA_BENCH_REPORT_H
#define LOTA_BENCH_REPORT_H

#include <stdio.h>

#include "result.h"

/*
 * bench_report - the session in @d, a result or a summary, as a table
 *
 * Each figure is the median over the runs of a configuration, warm-up
 * left out, with half the range of those runs as its spread. Returns 0,
 * or -EIO once @f has failed.
 */
int bench_report(FILE *f, const struct bench_doc *d);

/* the most an issue body holds */
#define BENCH_ISSUE_MAX_BYTES 65536

/*
 * bench_issue - the body of an issue reporting the session in @d
 *
 * The report, then the session's summary in a ```lota-bench block. The
 * summary is read back before it is written, and the body must fit an
 * issue. Returns 0, -EIO once @f has failed, or -EINVAL with the reason
 * in @err.
 */
int bench_issue(FILE *f, const struct bench_doc *d, char *err, size_t errcap);

#endif /* LOTA_BENCH_REPORT_H */
