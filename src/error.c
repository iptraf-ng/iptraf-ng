/***

error.c - Error-handling subroutines

Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997, 1998

This software is open source; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License in the included COPYING file for
details.

***/

#include "iptraf-ng-compat.h"
#include "tui/tui.h"

#include "error.h"
#include "log.h"

extern int daemonized;

void write_error(char *msg, ...)
{
	va_list vararg;

	va_start(vararg, msg);
	if (daemonized)
		write_daemon_err(msg, vararg);
	else
		tui_error_va(ANYKEY_MSG, msg, vararg);
	va_end(vararg);
}
