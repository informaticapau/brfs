/*
    BRFS
    Copyright (C) 2023 Ángel Ruiz Fernandez <arf20>
    Copyright (C) 2023 Bruno Castro García <bruneo32>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    log.c: Debug logging
*/

#include "log.h"

#include <stdarg.h>

void
debug_log(int e, const char *fmt, ...) {
    if (!e) return;
    va_list ap;
    va_start(ap, fmt);

    vprintf(fmt, ap);
}

void
aborterr(int errn, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    fprintf(stderr, fmt, ap);
    exit(errn);
}
