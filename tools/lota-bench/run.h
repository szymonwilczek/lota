/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench run - take the next run of a session
 */

#ifndef LOTA_BENCH_RUN_H
#define LOTA_BENCH_RUN_H

#define EXIT_BENCH_USAGE 2

/* the transient scope the game is started in, from its launch options */
#define BENCH_GAME_UNIT "lota-bench-game"

/* @argv[0] is "run"; returns the exit status */
int bench_main_run(int argc, char **argv);

#endif /* LOTA_BENCH_RUN_H */
