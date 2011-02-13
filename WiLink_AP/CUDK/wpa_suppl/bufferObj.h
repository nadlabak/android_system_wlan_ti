/*
 * bufferObj.h
 *
 * Copyright 2001-2009 Texas Instruments, Inc. - http://www.ti.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef _BUFFER_OBJ
#define _BUFFER_OBJ

#define STATUS int


/* Moved here from obsolete "pform_types_user.h" */
#define OK							0
#define NOK							1

typedef struct {
    u8 *pBase;		/* beginning of the over whole buffer */
	u8 *pCurrPos;	/* points to the current position in the buffer */
    u32 bufLen;		/* the total allocated length */
	u32 currOffset;	/* the offset of the pCurrPos ptr from pBase */
	u32 dataLen;		/* the length of the data stored */
	u8 allocated;	/* boolean */
} bufferObj;

/* "Constructor" for serializing operations, allocating default initial length. */
/* NOTE bufferFree should be called when this buffer has finished its role. */
STATUS bufferCreateChunk(bufferObj *buff);
/* "Constructor" for serializing operations, allocating exact length. */
/* NOTE bufferFree should be called when this buffer has finished its role. */
STATUS bufferCreateEmpty(bufferObj *buff, u32 length);
/* "Constructor" for Deserialize operations. */
/* Input: pointer to a previously-allocated data, and its length */
STATUS bufferCreateFill(bufferObj *buff, u8 *ptr, u32 length);


u8 *bufferPos(bufferObj *buff);
u32 bufferLength(bufferObj *buff);
u32 bufferRemaining(bufferObj *buff);
u8 *bufferGetBuf(bufferObj *buff);

u8 *bufferAdvance(bufferObj *buff, u32 offset);
u8 *bufferAppend(bufferObj *buff, u32 length, u8 *pBuff);
u8 *bufferSet(bufferObj *buff, u8 *pos);
u8 *bufferReset(bufferObj *buff);
u8 *bufferRewindX(bufferObj *buff, u32 length);
u8 *bufferRewindStart(bufferObj *buff);

void bufferFree(bufferObj *buff);
void bufferPrint(bufferObj *buff);
void bufferPrintX(bufferObj *buff);

#endif /* _BUFFER_OBJ */
