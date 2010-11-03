/*
    strbuf.h - string buffer

    Copyright (C) 2009  RedHat inc.

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
#ifndef STRBUF_H
#define STRBUF_H

struct strbuf
{
    /* Size of the allocated buffer. Always > 0. */
    int alloc;
    /* Length of the string, without the ending \0. */
    int len;
    char *buf;
};

/**
 * Creates and initializes a new string buffer.
 * @returns
 * It never returns NULL. The returned pointer must be released by
 * calling the function strbuf_free().
 */
struct strbuf *strbuf_new();

/**
 * Releases the memory held by the string buffer.
 * @param strbuf
 * If the strbuf is NULL, no operation is performed.
 */
void strbuf_free(struct strbuf *strbuf);

/**
 * Releases the strbuf, but not the internal buffer.  The internal
 * string buffer is returned.  Caller is responsible to release the
 * returned memory using free().
 */
char* strbuf_free_nobuf(struct strbuf *strbuf);

/**
 * The string content is set to an empty string, erasing any previous
 * content and leaving its length at 0 characters.
 */
void strbuf_clear(struct strbuf *strbuf);

/**
 * The current content of the string buffer is extended by adding a
 * character c at its end.
 */
struct strbuf *strbuf_append_char(struct strbuf *strbuf, char c);

/**
 * The current content of the string buffer is extended by adding a
 * string str at its end.
 */
struct strbuf *strbuf_append_str(struct strbuf *strbuf,
                                 const char *str);

/**
 * The current content of the string buffer is extended by inserting a
 * string str at its beginning.
 */
struct strbuf *strbuf_prepend_str(struct strbuf *strbuf,
                                  const char *str);

/**
 * The current content of the string buffer is extended by adding a
 * sequence of data formatted as the format argument specifies.
 */
struct strbuf *strbuf_append_strf(struct strbuf *strbuf,
                                  const char *format, ...);

/**
 * The current content of the string buffer is extended by inserting a
 * sequence of data formatted as the format argument specifies at the
 * buffer beginning.
 */
struct strbuf *strbuf_prepend_strf(struct strbuf *strbuf,
                                   const char *format, ...);

#endif
