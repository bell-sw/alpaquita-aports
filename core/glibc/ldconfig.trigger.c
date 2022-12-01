/*
 * This wrapper is used as an interpreter for glibc-utils.trigger so that
 * the trigger doesn't depend on /bin/sh as it may not be installed yet.
 *
 * The wrapper also guards ldconfig from any additional arguments that
 * are passed to invoke the intepreter, such as a pathname, which could
 * otherwise confuse ldconfig a lot.
 */

#include <unistd.h>

int main(void)
{
	char *const argv[] = {"/usr/sbin/ldconfig", NULL};

	return execv(argv[0], argv);
}
