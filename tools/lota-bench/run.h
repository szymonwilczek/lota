/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench run - take the next run of a session
 */

#ifndef LOTA_BENCH_RUN_H
#define LOTA_BENCH_RUN_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define EXIT_BENCH_USAGE 2

/* the transient scope the game is started in, from its launch options */
#define BENCH_GAME_UNIT "lota-bench-game"

/* @argv[0] is "run"; returns the exit status */
int bench_main_run(int argc, char **argv);

/* the newest MangoHud log in @dir since @since; 0, or -1 for none */
int bench_run_find_log(int dir, time_t since, char *name, size_t cap);

/* the session in @dir has warmed up in boot @boot */
bool bench_run_warm(int dir, const char *boot);

/* record @boot as the one the session in @dir warmed up in; 0, or -1 */
int bench_run_note_boot(int dir, const char *boot);

#endif /* LOTA_BENCH_RUN_H */
