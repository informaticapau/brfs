/*
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

    brfs.h: BRFS Specified structure definitions
*/

#ifndef _BRFS_H
#define _BRFS_H

#include <stdint.h>

/* Superblock up to ptr_size dependent fields */
typedef struct _brfs_superblock_base {
    char        br_magic[4];
    uint32_t    br_block_size;
    uint8_t     br_ptr_size; 
} brfs_superblock_base_t;

/* 16-bit pointer superblock */
typedef struct _brfs_superblock_16 {
    char        br_magic[4];
    uint8_t    br_block_size;
    uint8_t     br_ptr_size;
    uint16_t    br_free_space;
    uint16_t    br_first_free_block;
} brfs_superblock_16_t;

/* 32-bit pointer superblock */
typedef struct _brfs_superblock_32 {
    char        br_magic[4];
    uint8_t    br_block_size;
    uint8_t     br_ptr_size;
    uint32_t    br_free_space;
    uint32_t    br_first_free_block;

} brfs_superblock_32_t;

/* 64-bit pointer superblock */
typedef struct _brfs_superblock_64 {
    char        br_magic[4];
    uint8_t    br_block_size;
    uint8_t     br_ptr_size;
    uint64_t    br_free_space;
    uint64_t    br_first_free_block;
} brfs_superblock_64_t;


/* Directory entry attributes */
typedef struct _brfs_attr {
    uint16_t    br_mode;
    uint32_t    br_uid;
    uint32_t    br_gid;
    uint32_t    br_crtime;
    uint32_t    br_atime;
    uint32_t    br_mtime;
} brfs_attr_t;

/* 16-bit pointer directory entry */
typedef struct _brfs_dir_entry_16 {
    uint64_t    br_file_size;
    brfs_attr_t br_attributes;
    uint16_t    br_first_block;
    char        br_file_name_firstc;
} brfs_dir_entry_16_t;

/* 32-bit pointer directory entry */
typedef struct _brfs_dir_entry_32 {
    uint64_t    br_file_size;
    brfs_attr_t br_attributes;
    uint32_t    br_first_block;
    char        br_file_name_firstc;
} brfs_dir_entry_32_t;

/* 64-bit pointer directory entry */
typedef struct _brfs_dir_entry_64 {
    uint64_t    br_file_size;
    brfs_attr_t br_attributes;
    uint64_t    br_first_block;
    char        br_file_name_firstc;
} brfs_dir_entry_64_t;

#endif /* _BRFS_H */