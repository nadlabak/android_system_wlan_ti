/*
 * bufferObj.c
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

#include "includes.h"
#include "common.h"
#include "bufferObj.h"

#define BUFFER_CHUNK 1024

void *memcpy(void *dest, const void *src, size_t n);

/* Default constructor for Serealizing operations */
STATUS bufferCreateChunk(bufferObj *buff)
{
	buff->pBase = NULL; 
    buff->bufLen = BUFFER_CHUNK;

    buff->pBase = (u8 *) malloc(buff->bufLen);
	if( buff->pBase == NULL ) 
	{
		wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferCreateChunk: ERROR: Insufficient available memory");
		return NOK;
	}

    buff->currOffset = 0;
    buff->dataLen = 0; 
    buff->allocated = 1;
    buff->pCurrPos = buff->pBase;
    return OK;
}

STATUS bufferCreateEmpty(bufferObj *buff, u32 length)
{
	buff->pBase = NULL; 
    buff->bufLen = length;

    buff->pBase = (u8 *) malloc(buff->bufLen);
	if( buff->pBase == NULL ) 
	{
		wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferCreateEmpty: ERROR: Insufficient available memory");
		return NOK;
	}

    buff->currOffset = 0;
    buff->dataLen = 0; 
    buff->allocated = 1;
    buff->pCurrPos = buff->pBase;
	return OK;
}

/*
* Overloaded constructor for Deserialize operations.
*  Once data is in this bufferObj, it's easier to parse it.
* Input: pointer to a previously-allocated data, and its length
*/
STATUS bufferCreateFill(bufferObj *buff, u8 *ptr, u32 length)
{
	buff->pBase = ptr; 
    buff->pCurrPos = ptr;
    buff->bufLen = length;
    buff->currOffset = 0;
    buff->dataLen = length; 
    buff->allocated = 0;

	return OK;
}

u8 *bufferAdvance(bufferObj *buff, u32 offset)
{
    /* Advance the pCurrPos pointer. update current length */
	/*	Don't disturb the dataLength variable here */
	if(buff->currOffset + offset > buff->bufLen)
	{
		wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferAdvance: ERROR: overflow. returns NULL.");
		return NULL;
	}
    
    buff->currOffset += offset;
    buff->pCurrPos += offset;
    return buff->pCurrPos;
}

u8 *bufferAppend(bufferObj *buff, u32 length, u8 *pBuff)
{
    if((pBuff == NULL) || (length == 0))
	{
		wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferAppend: ERROR: (pBuff == NULL) || (length == 0)");
		return buff->pCurrPos;
	}

    /* IMPORTANT: if this buffer was not allocated by us */
    /*	and points to an existing buffer, then we should be extremely careful */
    /*	how much data we append */
    if((!buff->allocated) && (bufferRemaining(buff) < length))
    {
    	u8 *ptr;

		wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferAppend: Explicitly allocating memory");

		/* now we need to explicitly allocate memory. */
		/* while in the process, allocate some extra mem */
		ptr = (u8 *) malloc(buff->bufLen+BUFFER_CHUNK);
		if( ptr == NULL ) 
		{
			wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferAppend: ERROR: Insufficient available memory.");
			return NULL;
		}

		/* copy the existing data */
		memcpy(ptr, buff->pBase, buff->currOffset);

		/* update internal variables */
		buff->pBase = ptr;
		buff->pCurrPos = buff->pBase + buff->currOffset;
		buff->bufLen += BUFFER_CHUNK;
		buff->allocated = 1;
    }

    if(buff->bufLen - buff->currOffset < length)
    {
		u32 tempLen = (length>BUFFER_CHUNK)?length:BUFFER_CHUNK;

		wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferAppend: Explicitly reallocating memory");

		buff->pBase = (u8 *)realloc(buff->pBase, buff->currOffset+tempLen);
		if( buff->pBase == NULL ) 
		{
			wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferAppend: ERROR: realloc failure.");
			return NULL;
		}

		buff->bufLen = (buff->currOffset+tempLen);
		buff->pCurrPos = buff->pBase + buff->currOffset;
    }

    memcpy(buff->pCurrPos, pBuff, length);

    buff->pCurrPos += length;
    buff->currOffset += length;

    /* the data length needs to be updated based on the pointer locations, */
    /*	since the pointers could have been moved around (using rewind and */
    /*	advance) before the call to append. */
    buff->dataLen = buff->pCurrPos - buff->pBase;

    return buff->pCurrPos-length; /* return the location at which the data was copied */
}

u8 *bufferSet(bufferObj *buff, u8 *pos)
{
	u32 offset;
    if ((pos < buff->pBase) || (pos > (buff->pBase + buff->bufLen)))
   	{
		wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferSet: ERROR: Buffer underflow.");
		return NULL;
	}
   
    /* Perform operation as if pos lies before pCurrPos. */
    /*	If it lies after pCurrPos, offset will be negative, so we'll be OK */
    offset = (u32)(buff->pCurrPos-pos);
    buff->pCurrPos = pos;
    buff->currOffset -= offset;
    return buff->pCurrPos;
}

u8 *bufferReset(bufferObj *buff)
{
    buff->pCurrPos = buff->pBase;
    buff->currOffset = buff->dataLen = 0;
    return buff->pBase;
}

u8 *bufferRewindX(bufferObj *buff, u32 length)
{
    if(length > buff->currOffset)
	{
		wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferRewindX: ERROR: Buffer underflow.");
		return NULL;
	}

    buff->currOffset -= length;
    buff->pCurrPos = buff->pBase + buff->currOffset;
    return buff->pCurrPos;
}

u8 *bufferRewindStart(bufferObj *buff)
{
    buff->currOffset = 0;
    buff->pCurrPos = buff->pBase;
    return buff->pCurrPos;
}

void bufferFree(bufferObj *buff)
{
    if((buff->allocated) && (buff->pBase))
    {
		free(buff->pBase);
		buff->allocated = 0;
    }
	buff->pBase = NULL;
	buff->pCurrPos = NULL;
	buff->bufLen = 0;
	buff->currOffset = 0;
	buff->dataLen = 0;
}

u8 *bufferPos(bufferObj *buff) 
{ 
	return buff->pCurrPos;  
}
u32 bufferLength(bufferObj *buff) 
{ 
	return buff->dataLen; 
}
u32 bufferRemaining(bufferObj *buff) 
{ 
	return buff->bufLen - buff->currOffset;  
}
u8 *bufferGetBuf(bufferObj *buff) 
{ 
	return buff->pBase; 
}

void bufferPrint(bufferObj *buff)
{
	u8 *str= NULL; 
	u16 len;

	len=bufferLength(buff)+1;
	str= (u8*) malloc(len);
	if( str == NULL ) 
	{
		wpa_printf(MSG_ERROR,"BUFFER_OBJ: bufferPrint: ERROR: Insufficient available memory.");
		return ;
	}
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrint: Length: %d", len);

	memcpy(str,bufferGetBuf(buff),len-1);
	*(str+len-1)='\0';

	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrint: %s", str);
}

void bufferPrintX(bufferObj *buff) 
{
	u8 *pCurrByte= NULL; 
	u16 len;
	
	len=bufferLength(buff);
	pCurrByte=buff->pBase;
	
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: pBase: 0x%x", (unsigned int)buff->pBase);
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: pCurrPos: 0x%x", (unsigned int)buff->pCurrPos);
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: bufLen: %d", buff->bufLen);
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: currOffset: %d", buff->currOffset);
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: dataLen: %d", buff->dataLen);
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: allocated: %d", buff->allocated);
	
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: Beginning Of Buffer");
	while (len--)
	{
		printf(" %x",*pCurrByte++);         
	}
	wpa_printf(MSG_DEBUG,"BUFFER_OBJ: bufferPrintX: End Of Buffer");
}
