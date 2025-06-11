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
	pid_t			pid;
	struct test		*test;
	int			status;

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

	TAILQ_FOREACH(test, &tests, list) {
		if (WIFEXITED(test->status) && WEXITSTATUS(test->status) == 0) {
			printf("  %s: success\n", test->name);
		} else {
			printf("  %s: failed (%d)\n", test->name, test->status);
		}
	}
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
