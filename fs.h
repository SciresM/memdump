#ifndef _FS_H
#define _FS_H

#include "types.h"

struct File {
	s32 s;
	u32 pos;
	u32 size;
};

#define FILE_R 0x01
#define FILE_W 0x06

int (*IFile_Open)(struct File *f, const short *path, int flags) = (void *)0x0022FE08;
int (*IFile_Read)(struct File *f, unsigned int *read, void *buffer, unsigned int size) = (void *)0x001686DC;
int (*IFile_Write)(struct File *f, unsigned int *written, void *src, unsigned int len) = (void *)0x00168764;

#endif

