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

#include "iptraf-ng-compat.h"

#include "dirs.h"

char *get_path(int dirtype, char *file)
{
    static char path[PATH_MAX];
    char *ptr = NULL;
    char *dir, *env = NULL;

    switch (dirtype) {
    case T_WORKDIR:
        dir = WORKDIR;
        env = WORKDIR_ENV;
        break;
    case T_LOGDIR:
        dir = LOGDIR;
        env = LOGDIR_ENV;
        break;
    case T_LOCKDIR:
        dir = LOCKDIR;
        break;
    default:
        return file;
    }

    if ((dirtype != T_LOCKDIR)
	&& (ptr = getenv(env)) != NULL)
        dir = ptr;

    if (dir == NULL || *dir == '\0')
        return file;

    snprintf(path, PATH_MAX - 1, "%s/%s", dir, file);

    return path;
}
