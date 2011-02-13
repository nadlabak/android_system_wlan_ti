/*
 * CipherWrapper.c
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

/* OpenSSL includes */
#include "ossl_typ.h"
#include "rand.h"
#include "bn.h"
#include "dh.h"
#include "err.h"
#include "sha.h"
#include "openssl-0.9.8e/include/openssl/evp.h"
#include "hmac.h"



#include "bufferObj.h"
#include "CipherWrapper.h"
#include "WscTypes.h"
#include <string.h>





static u8 DH_P_VALUE[BUF_SIZE_1536_BITS] = 
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static u32 DH_G_VALUE = 2;



/***************************************************************************/
 
u32 cipherGenerateDHKeyPair(DH **DHKeyPair)
{
    /* u8 temp[SIZE_PUB_KEY] = {0}; */
	//int len = 0;
	u32 g = 0;
	//u8 * buffLoc = NULL;
    
	/* 1. Initialize the DH structure */
	*DHKeyPair = DH_new();
	if(*DHKeyPair == NULL)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: DH_new failed\n");
		return NOK;
	}
	
	(*DHKeyPair)->p = BN_new();
	if((*DHKeyPair)->p == NULL)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: BN_new failed\n");
		DH_free(*DHKeyPair);
		return NOK;
	}

	(*DHKeyPair)->g = BN_new();
	if((*DHKeyPair)->g == NULL)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: BN_new failed\n");
		BN_free((*DHKeyPair)->p);
		DH_free(*DHKeyPair);
		return NOK;
	}
	
	/* 2. load the value of P */
	if(BN_bin2bn(DH_P_VALUE, 
		BUF_SIZE_1536_BITS, 
		(*DHKeyPair)->p)==NULL)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: BN_bin2bn P: %s", 
			ERR_error_string(ERR_get_error(), NULL));
		BN_free((*DHKeyPair)->p);
		BN_free((*DHKeyPair)->g);
		DH_free(*DHKeyPair);
		return NOK;
	}
	
	/* 3. load the value of G */
	g = htonl(DH_G_VALUE);   
	if(BN_bin2bn((u8 *)&g, 
		4, 
		(*DHKeyPair)->g)==NULL)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: BN_bin2bn G: %s", 
			ERR_error_string(ERR_get_error(), NULL));
		BN_free((*DHKeyPair)->p);
		BN_free((*DHKeyPair)->g);
		DH_free(*DHKeyPair);
		return NOK;
	}
	
	/* 4. generate the DH key */
	if(DH_generate_key(*DHKeyPair) == 0)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: DH_generate_key: %s", 
			ERR_error_string(ERR_get_error(), NULL));
		BN_free((*DHKeyPair)->p);
		BN_free((*DHKeyPair)->g);
		DH_free(*DHKeyPair);
		return NOK;
	}
	/*
	5. extract the DH public key .
	len = BN_bn2bin((*DHKeyPair)->pub_key, temp);
	if(0 == len)
	{
		printf("%s: BN_bn2bin failed\n",__FUNCTION__);
		return NOK;
	}

	buffLoc = bufferAppend(pubKey,SIZE_PUB_KEY,temp);
	if (!buffLoc)
	{
		return NOK;
	}*/
	return OK;
}


u32 cipherGenerateSHA256Hash(bufferObj* inBuf, bufferObj* outBuf)
{
	u8  * buffLoc = 0;
	u8 Hash[SIZE_256_BITS] = {0};
	if(SHA256(bufferGetBuf(inBuf), bufferLength(inBuf), Hash) == NULL)
    {
        wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: SHA256 calculation failed");
        return NOK;
    }
	
	buffLoc = bufferAppend(outBuf,SIZE_256_BITS,Hash);
	if (!buffLoc)
	{
		return NOK;
	}
	return OK;
}

u32 cipherDeriveKey(bufferObj* KDK, bufferObj* prsnlString, u32 keyBits, bufferObj* key)
{
	int i=0, iterations = 0, temp;
    bufferObj input, output;    
    u8 hmac[SIZE_256_BITS];
    u32 hmacLen = 0;
    u8 *inPtr = 0;
	u8 * buffLoc = 0;

	bufferCreateEmpty(&input, SIZE_256_BITS);
	bufferCreateEmpty(&output, SIZE_256_BITS);

    iterations = ((keyBits/8) + PRF_DIGEST_SIZE - 1)/PRF_DIGEST_SIZE;
	temp = htonl(i);
	
	buffLoc = bufferAppend(&input,sizeof(i),(u8 *)&temp);
	if (!buffLoc)
	{
		bufferFree(&input);
		bufferFree(&output);
		return NOK;
	}	
	buffLoc = bufferAppend(&input,bufferLength(prsnlString),bufferGetBuf(prsnlString));
	if (!buffLoc)
	{
		bufferFree(&input);
		bufferFree(&output);
		return NOK;
	}

	temp = htonl(keyBits);
	buffLoc = bufferAppend(&input,sizeof(keyBits),(u8 *)&temp);
	if (!buffLoc)
	{
		bufferFree(&input);
		bufferFree(&output);
		return NOK;
	}

	inPtr = bufferGetBuf(&input);

    for(i = 0; i < iterations; i++)
    {
        /* Set the current value of i at the start of the input buffer */
        *(int *)inPtr = htonl(i+1);
        if(HMAC(EVP_sha256(), bufferGetBuf(KDK), SIZE_256_BITS, bufferGetBuf(&input), 
                bufferLength(&input), hmac, &hmacLen) == NULL)
        {
			wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherDeriveKey: HMAC failed");
			bufferFree(&input);
			bufferFree(&output);
            return NOK;
        }
        
		buffLoc = bufferAppend(&output,hmacLen,hmac);
		if (!buffLoc)
		{
			bufferFree(&input);
			bufferFree(&output);
			return NOK;
		}
    }

    /* Sanity check */
    if(keyBits/8 > bufferLength(&output))
    {
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherDeriveKey: Key derivation generated less bits than asked");
		bufferFree(&input);
		bufferFree(&output);
		return NOK;
    }

    /* We now have at least the number of key bits requested. */
    /* Return only the number of bits asked for. Discard the excess. */
	buffLoc = bufferAppend(key,keyBits/8,bufferGetBuf(&output));
	if (!buffLoc)
	{
		bufferFree(&input);
		bufferFree(&output);
		return NOK;
	}
	bufferFree(&input);
	bufferFree(&output);
	return OK;
}


u32 cipherEncrypt(	bufferObj* plainText, 
						bufferObj* encrKey, 
						bufferObj* authKey, 
						bufferObj* cipherText, 
						bufferObj* iv)
{
	u8* buffLoc = 0;
	bufferObj buf;
    u8 ivBuf[SIZE_128_BITS];
    EVP_CIPHER_CTX ctx;
	int bufLen = 0;
    u8 outBuf[1024];
    int outLen, currentLength;
	int blockSize; 
    int length;
	u8* bufPtr = NULL;

    if(0 == bufferLength(plainText))
	{
        return NOK;
	}

    /* Generate a random iv */
    RAND_bytes(ivBuf, SIZE_128_BITS);
	bufferReset(iv);
		
   	buffLoc = bufferAppend(iv,SIZE_128_BITS,(u8 *)ivBuf);
	
	if (!buffLoc)
	{
		return NOK;
	}

	/* Now encrypt the plaintext and mac using the encryption key and IV. */

	bufferCreateChunk(&buf);
		
	bufferReset(&buf);
	buffLoc = bufferAppend(&buf,bufferLength(plainText),bufferGetBuf(plainText));
		
	if (!buffLoc)
	{
		bufferFree(&buf);
		return NOK;
	}
	
    if(0 == EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), bufferGetBuf(encrKey), ivBuf))
    {
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherEncrypt: EncryptInit failed");
		bufferFree(&buf);
        return NOK;
    }
	
    bufLen = 1024;
    /* block size = 1024 bytes - 128 bits, */
    /* leave 128 bits at the end to accommodate any possible padding */
    /* and avoid a buffer overflow */
    blockSize = bufLen - SIZE_128_BITS;
	
    length = bufferLength(&buf);
	
    bufPtr = bufferGetBuf(&buf);
	
    while(length)
    {
		
        if(length > blockSize)
            currentLength = blockSize;
        else
			currentLength = length;
		
        if(0 == EVP_EncryptUpdate(&ctx, outBuf, &outLen, bufPtr, currentLength))
        {
			wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherEncrypt: EncryptUpdate failed");
			bufferFree(&buf);
            return NOK;
        }
		
		buffLoc = bufferAppend(cipherText,outLen,(u8 *)outBuf);
		if (!buffLoc)
		{
			bufferFree(&buf);
			return NOK;
		}
			
		bufPtr = bufferAdvance(&buf,currentLength);
		if (!bufPtr)
		{
			wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherEncrypt: Internal Error: bufferAdvance failed");
			bufferFree(&buf);
			return NOK;
		}
        length -= currentLength;
    }
	
    if(0 == EVP_EncryptFinal(&ctx, outBuf, &outLen))
    {
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherEncrypt: EncryptFinal failed");
		bufferFree(&buf);
        return NOK;
    }
	
    buffLoc = bufferAppend(cipherText,outLen,(u8 *)outBuf);
	if (!buffLoc)
	{
		bufferFree(&buf);
		return NOK;
	}
    bufferFree(&buf);
	return OK;
}

u32 cipherDecrypt(	bufferObj* cipherText, 
						bufferObj* iv,
						bufferObj* encrKey, 
						bufferObj* authKey, 
						bufferObj* plainText)
{
	EVP_CIPHER_CTX ctx;
    bufferObj buf;
	u8* buffLoc = 0;
    int bufLen = 1024;
    u8 outBuf[1024];
    int outLen, currentLength;
    /* block size = 1024 bytes - 128 bits, */
    /* leave 128 bits at the end to accommodate any possible padding */
    /* and avoid a buffer overflow */
    int blockSize = bufLen - SIZE_128_BITS; 
    int length = bufferLength(cipherText);

    u8 *bufPtr = bufferGetBuf(cipherText);
	bufferRewindStart(cipherText);
	bufferRewindStart(iv);
	bufferRewindStart(encrKey);
	bufferRewindStart(authKey);
	bufferRewindStart(plainText);
	bufferCreateChunk(&buf);

	if(0 == EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), bufferGetBuf(encrKey), bufferGetBuf(iv)))
    {
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherDecrypt: DecryptInit failed");
		bufferFree(&buf);
        return NOK;
    }
	
    while(length)
    {
        if(length > blockSize)
            currentLength = blockSize;
        else
            currentLength = length;

		

        if(0 == EVP_DecryptUpdate(&ctx, outBuf, &outLen, bufPtr, currentLength))
        {
			wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherDecrypt: DecryptUpdate failed");
			bufferFree(&buf);
            return NOK;
        }

		if (outLen)
		{
        buffLoc = bufferAppend(&buf, outLen, (u8*)outBuf);

		if (!buffLoc)
		{
			bufferFree(&buf);
			return NOK;
		}
		}

		bufPtr = bufferAdvance(cipherText, currentLength);

		if (!bufPtr)
		{
			wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherDecrypt: Internal Error: bufferAdvance failed");
			bufferFree(&buf);
			return NOK;
		}

        length -= currentLength;
    }

    if(0 == EVP_DecryptFinal(&ctx, outBuf, &outLen))
    {
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherDecrypt: DecryptFinal failed");
		bufferFree(&buf);
        return NOK;
    }

	if (outLen)
	{
	buffLoc = bufferAppend(&buf, outLen, (u8*)outBuf);
	if (!buffLoc)
	{
		bufferFree(&buf);
		return NOK;
	}
	}
   
	if (bufferGetBuf(&buf) && bufferLength(&buf))
	{
	buffLoc = bufferAppend(plainText, bufferLength(&buf), bufferGetBuf(&buf));
	if (!buffLoc)
	{
		bufferFree(&buf);
		return NOK;
	}
	}

	bufferFree(&buf);
    return OK;
}




u8 cipherValidateMac(bufferObj *data, u8 *hmac, bufferObj *key)
{
	
	u8 dataMac[SIZE_256_BITS];

	/* First calculate the hmac of the data */
	if(HMAC(EVP_sha256(), bufferGetBuf(key), SIZE_256_BITS, bufferGetBuf(data), 
	bufferLength(data), dataMac, NULL) == NULL)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherValidateMac: HMAC failed");
	return NOK;
	}

	/* next, compare it against the received hmac */
	if(memcmp(dataMac, hmac, SIZE_256_BITS) != 0)
	{
		wpa_printf(MSG_ERROR, "CIPHER_WRAPPER: cipherValidateMac: HMAC results don't match");
	return NOK;
	}

	return OK;
	
}

