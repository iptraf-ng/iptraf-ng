#include "iptraf-ng-compat.h"


static void vreportf(const char *prefix, const char *err, va_list params)
{
	char msg[4096];
	vsnprintf(msg, sizeof(msg), err, params);
	fprintf(stderr, "%s%s\n", prefix, msg);
}

static NORETURN void die_buildin(const char *err, va_list params)
{
	vreportf("fatal: ", err, params);
	exit(129);
}

static NORETURN void error_buildin(const char *err, va_list params)
{
	vreportf("error: ", err, params);
}

void die(const char *err, ...)
{
	va_list params;

	va_start(params, err);
	die_buildin(err, params);
	va_end(params);
}

void error(const char *err, ...)
{
	va_list params;

	va_start(params, err);
	error_buildin(err, params);
	va_end(params);
}
