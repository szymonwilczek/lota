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

#endif /* LOTA_BENCH_REPORT_H */
