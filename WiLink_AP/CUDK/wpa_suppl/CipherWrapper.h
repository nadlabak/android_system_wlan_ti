/*
 * CipherWrapper.h
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

#ifndef _CIPHER_WRAPPER_
#define _CIPHER_WRAPPER_

u32 cipherGenerateDHKeyPair(DH **DHKeyPair);

u32 cipherGenerateSHA256Hash(bufferObj *inBuf, bufferObj *outBuf);

u32 cipherDeriveKey(bufferObj *KDK, bufferObj *prsnlString, u32 keyBits, bufferObj *key);

u32 cipherEncrypt(bufferObj *plainText, 
				 bufferObj *encrKey, 
				 bufferObj *authKey, 
				 bufferObj *cipherText, 
				 bufferObj *iv);

u32 cipherDecrypt(bufferObj *cipherText, 
				 bufferObj *iv,
				 bufferObj *encrKey, 
				 bufferObj *authKey, 
				 bufferObj *plainText);
u8 cipherValidateMac(bufferObj *data, u8 *hmac, bufferObj *key);


#endif /* _CIPHER_WRAPPER_ */
