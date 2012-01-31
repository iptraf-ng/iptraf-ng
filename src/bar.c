/*
    Copyright (C) 2011  Nikola Pajkovsky (npajkovs@redhat.com)

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

// TODO: full rewrite

/*
 * Set the highlight bar to point to the specified entry.
 * This routine also sets the cleared flag (indicates whether the
 * flow rate has been displayed).  The flow rate computation timer
 * and accumulator are also reset.
 */

#include "iptraf-ng-compat.h"

#include "attrs.h"

void set_barptr(void **barptr, void *entry, time_t * starttime, void *spanbr,
		size_t size, WINDOW * win, int *cleared, int x)
{
	*barptr = entry;
	*starttime = time(NULL);
	memset(spanbr, 0, size);

	if (!(*cleared)) {
		wattrset(win, IPSTATATTR);
		mvwprintw(win, 0, x, "Computing");
		tx_wcoloreol(win);
		*cleared = 1;
	}
}
