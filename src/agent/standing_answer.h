/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Whether a repeated answer is news. The agent re-answers unchanging questions
 * on a timer (measurable code, token issuance); callers own printing, storage
 * and keys. Terms as for a decision-log row in contracts.rst: a first answer
 * is written unless it is NOTHING_WRONG, a change is written both ways,
 * and the rendered statement, not the verdict, is compared.
 */

#ifndef LOTA_AGENT_STANDING_ANSWER_H
#define LOTA_AGENT_STANDING_ANSWER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* a longer statement is truncated, not dropped */
#define STANDING_ANSWER_STATEMENT_MAX 768

/* zero answer: news only when it replaces another */
#define STANDING_ANSWER_NOTHING_WRONG 0

struct standing_answer {
	bool seen; /* anything recorded yet */
	bool stated; /* reached the log */
	int answer;
	uint64_t repeats; /* rounds repeating it since recorded */
	char statement[STANDING_ANSWER_STATEMENT_MAX];
};

/*
 * standing_answer_note - Record a round's answer
 * @answer_state: subject's standing answer, NULL to state everything
 * @answer: this round's answer
 * @statement: rendered line, compared; NULL compares as empty
 * @held: on a change, rounds the replaced answer stood
 *
 * Return: true when the answer is worth a line.
 */
static inline bool standing_answer_note(struct standing_answer *answer_state,
					int answer, const char *statement,
					uint64_t *held)
{
	const char *text = statement ? statement : "";

	if (held)
		*held = 0;

	/* nowhere to remember it, so it cannot be a known repeat */
	if (!answer_state)
		return true;

	if (answer_state->seen && answer_state->answer == answer &&
	    strcmp(answer_state->statement, text) == 0) {
		answer_state->repeats++;
		return false;
	}

	if (answer_state->seen) {
		if (held)
			*held = answer_state->repeats;
		/* a change is news both ways, recovery included */
		answer_state->stated = true;
	} else {
		answer_state->stated = answer != STANDING_ANSWER_NOTHING_WRONG;
	}

	answer_state->seen = true;
	answer_state->answer = answer;
	answer_state->repeats = 0;
	snprintf(answer_state->statement, sizeof(answer_state->statement), "%s",
		 text);
	return answer_state->stated;
}

/* Forget a subject, so its next answer is news */
static inline void standing_answer_forget(struct standing_answer *answer_state)
{
	if (answer_state)
		memset(answer_state, 0, sizeof(*answer_state));
}

/*
 * Clause giving the length of the run just ended; kept out of the compared
 * statement, which would otherwise change every round.
 */
static inline void standing_answer_held_clause(char *out, size_t cap,
					       uint64_t held)
{
	if (!out || cap == 0)
		return;

	if (held == 0) {
		out[0] = '\0';
		return;
	}

	snprintf(out, cap, " (the previous answer held %llu further round%s)",
		 (unsigned long long)held, held == 1 ? "" : "s");
}

#endif /* LOTA_AGENT_STANDING_ANSWER_H */
