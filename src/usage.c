/*
    Copyright (C) 2010  Nikola Pajkovsky (npajkovs@redhat.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

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

static void error_buildin(const char *err, va_list params)
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
