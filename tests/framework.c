/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "framework.h"

#define COLOR_RED	"\033[31m"
#define COLOR_GREEN	"\033[32m"
#define COLOR_RESET	"\033[0m"

/*
 * A single test with its name and callback function. The child process
 * its exit status is recorded in status.
 */
struct test {
	pid_t			pid;
	int			status;

	const char		*name;
	void			(*entry)(void);

	TAILQ_ENTRY(test)	list;
};

/* List of all tests that are registered by test_framework_register(). */
static TAILQ_HEAD(, test)		tests;

/*
 * Testing entry point, we immediately hand over control to the test
 * its test_entry() function that it should have defined.
 */
int
main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	TAILQ_INIT(&tests);

	test_entry();

	return (0);
}

/*
 * Registers a new test to be executed when test_framework_run() is called.
 * The test gets a name and entry point that is called.
 */
void
test_framework_register(const char *name, void (*entry)(void))
{
	struct test	*test;

	if ((test = calloc(1, sizeof(*test))) == NULL)
		fatal("calloc failed");

	test->name = name;
	test->entry = entry;

	TAILQ_INSERT_TAIL(&tests, test, list);
}

/*
 * Run all tests by forking for each test and waiting for its exit.
 * A normal exit code of 0 means the test went OK, anything else is fail.
 */
void
test_framework_run(void)
{
	pid_t		pid;
	struct test	*test;
	const char	*pass, *fail, *reset;
	int		status, failed, total, color;

	color = isatty(STDOUT_FILENO);
	pass = color ? COLOR_GREEN : "";
	fail = color ? COLOR_RED : "";
	reset = color ? COLOR_RESET : "";

	printf("Test schedule\n");
	TAILQ_FOREACH(test, &tests, list)
		printf("  %s\n", test->name);

	printf("\nRunning\n");

	TAILQ_FOREACH(test, &tests, list) {
		if ((test->pid = fork()) == -1) {
			printf("failed to execute '%s', cannot fork (%s)\n",
			    test->name, strerror(errno));
			continue;
		}

		if (test->pid == 0) {
			test->entry();
			exit(0);
		}
	}

	for (;;) {
		if ((pid = waitpid(-1, &status, WNOHANG)) == -1) {
			if (errno == ECHILD)
				break;
			fatal("waitpid: %s", strerror(errno));
		}

		TAILQ_FOREACH(test, &tests, list) {
			if (test->pid != pid)
				continue;

			test->status = status;
		}
	}

	failed = 0;
	total = 0;

	TAILQ_FOREACH(test, &tests, list) {
		total++;

		if (WIFEXITED(test->status) && WEXITSTATUS(test->status) == 0) {
			printf("  %s[PASS]%s %s\n", pass, reset, test->name);
			continue;
		}

		failed++;

		if (WIFEXITED(test->status)) {
			printf("  %s[FAIL]%s %s (exit code %d)\n",
			    fail, reset, test->name,
			    WEXITSTATUS(test->status));
		} else if (WIFSIGNALED(test->status)) {
			printf("  %s[FAIL]%s %s (%d)\n", fail, reset,
			    test->name, WTERMSIG(test->status));
		} else {
			printf("  %s[FAIL]%s %s (status 0x%x)\n",
			    fail, reset, test->name, test->status);
		}
	}

	printf("\nSummary: %s%d/%d passed%s", failed == 0 ? pass : fail,
	    total - failed, total, reset);
	if (failed != 0)
		printf(", %s%d failed%s", fail, failed, reset);
	printf("\n");

	exit(failed == 0 ? 0 : 1);
}

/* Bad juju happened. */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	printf("\n");

	exit(1);
}
