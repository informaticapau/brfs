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

    brfs_fuse.h: Filesystem in Userspace implementation for BRFS
*/

#include <stdio.h>

#define FUSE_USE_VERSION    26
#define _FILE_OFFSET_BITS   64
#include <fuse.h>


struct brfs_fuse_state {
    char *rootdir;
};

#define BRFS_FUSE_DATA ((struct brfs_fuse_state*)fuse_get_context()->private_data)

void
usage() {

}

int main(int argc, char **argv) {
    /* Check arguments */
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
	    usage();

    
}
