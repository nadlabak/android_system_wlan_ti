/*
 * eap_wsc.c
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

#include "ossl_typ.h"
#include "rand.h"
#include "bn.h"
#include "dh.h"
#include "sha.h"
#include "openssl-0.9.8e/include/openssl/evp.h"
#include "hmac.h"
#include "err.h"

#include "common.h"
#include "eap_i.h"

#include "bufferObj.h"
#include "CipherWrapper.h"
#include "WscTypes.h"
#include "wsc_supplicant.h"
#include "config_ssid.h"

/* WSC Message types (opCode) */
#define WSC_Start 			0x01
#define WSC_ACK   			0x02
#define WSC_NACK  			0x03
#define WSC_MSG   			0x04
#define WSC_Done  			0x05

#define WSC_EAP_CODE_RESPONSE		2
#define WSC_EAP_TYPE				254
#define WSC_VENDORID_0				0x00
#define WSC_VENDORID_1				0x37
#define WSC_VENDORID_2				0x2A
#define WSC_VENDORTYPE				0x00000001
#define WSC_EAP_PACKET_HEADER_LEN	14

#define MAC_ADDRESS_SIZE	6

#define PERSONALIZATION_STRING  "Wi-Fi Easy and Secure Key Derivation"

typedef enum {
    WSC_ID_MESSAGE_START= 0x00, 
    WSC_ID_MESSAGE_M1	= 	0x04,
    WSC_ID_MESSAGE_M2	= 	0x05,
    WSC_ID_MESSAGE_M2D = 	0x06,
    WSC_ID_MESSAGE_M3	= 	0x07,
    WSC_ID_MESSAGE_M4	= 	0x08,
    WSC_ID_MESSAGE_M5	= 	0x09,
    WSC_ID_MESSAGE_M6	= 	0x0A,
    WSC_ID_MESSAGE_M7	= 	0x0B,
    WSC_ID_MESSAGE_M8	= 	0x0C,
	WSC_ID_MESSAGE_ACK = 	0x0D,
	WSC_ID_MESSAGE_NACK =	0x0E,
    WSC_ID_MESSAGE_DONE =	0x0F,
    WSC_ID_MESSAGE_UNKNOWN = 0xFF
} EEapWscMsgType;

/* data structures for each instance of registration protocol */
typedef enum {
    EAP_WSC_STATE_START = 0,
    EAP_WSC_STATE_CONTINUE,
    EAP_WSC_STATE_SUCCESS, 
    EAP_WSC_STATE_FAILURE
} EEapWsc_SMState;

typedef struct
{
	u16 				category_id;
	u32 				oui; /* =0x0050F204 */
	u16 				sub_category_id;
}	TEapWsc_DeviceType;

typedef struct
{
	u8					isValid;  
	u8					macAddress[MAC_ADDRESS_SIZE];
	TEapWsc_DeviceType	peerType;
	char				deviceName[MAX_DEVICE_NAME]; /* (0x1011) */
	u8					password[MAX_PASSWORD_SIZE]; /* PIN */
	u8 					uuidR[16]; /* (0x1048) */
	u16 				authenticationTypeFlags; /* (0x1004) */
	u16 				encryptionTypeFlags; /* (0x1010) */
	u8 					connectionTypeFlags; /* (0x100D) */
	u16 				configMethods; /* (0x1008) */
	char 				manufacturer[MAX_MANUFACTURER]; /* (0x1021) */
	char 				modelName[MAX_MODEL_NAME]; /* (0x1023) */
	char 				modelNumber[MAX_MODEL_NUMBER]; /* (0x1024) */
	char 				serialNumber[MAX_SERIAL_NUMBER]; /* (0x1042) */
	u16 				serialNumberLength;
	TEapWsc_DeviceType 	primaryDeviceType; /* (0x1054) */
	u8 					rfBand; /* (0x103C) */
	u16 				assocState; /* (0x1002) */
	u16 				configError; /* (0x1009) */
	u16 				devicePasswordId; /* (0x1012) */
	u32 				osVersion; /* (0x102D) */

} TEapWsc_DeviceInfo;

typedef struct
{
	TWscSupplicant* pWscSupplicantConfig;
	EEapWsc_SMState 	smState;
    struct eap_sm 		*sm;

	u8       			enrolleeNonce[SIZE_128_BITS]; /* N1 */
	u8       			registrarNonce[SIZE_128_BITS]; /* N2 */

	BIGNUM      		*DH_PubKey_Peer; /* peer's pub key stored in bignum format */
	DH          		*DHSecret;       /* local key pair in bignum format */
	
	u8       			pke[SIZE_PUB_KEY]; /* enrollee's raw pub key */
	u8					pkr[SIZE_PUB_KEY]; /* registrar's raw pub key */

	bufferObj			authKey;
	bufferObj   		keyWrapKey;
    //bufferObj   		emsk;

	u8       			psk1[SIZE_128_BITS];
    u8					psk2[SIZE_128_BITS];

	u8					es1[SIZE_128_BITS];
    u8					es2[SIZE_128_BITS];

	u8					eHash1[SIZE_256_BITS];
    u8					eHash2[SIZE_256_BITS];

	u8       			rs1[SIZE_128_BITS];
    u8       			rs2[SIZE_128_BITS];

	u8					rHash1[SIZE_256_BITS];
    u8					rHash2[SIZE_256_BITS]; 

	u32					LastMessageSent;
	u32					LastMessageRecv;

	/* in/outMsg must store previous message in order to compute hash */
    bufferObj   		InMsg;      /* Received message will be stored here */
    bufferObj   		OutMsg;     /* Contains message to be transmitted */

	TEapWsc_DeviceInfo	*pPeerDeviceInfo;        

	TStaEncryptSettings	*pStaEncryptSettings;
	
} TEapWsc;

typedef struct
{
    u8 	code;
    u8 	id;
    u16	len; /* of the entire eap packet, i.e. including header and data */
    u8 	type;
    u8 	vendorId[3];
    u32 vendorType;
	u8 	opCode;
	u8 	flags;	/* The message might be fragmented, flag for first fragment (only he carries the size of the message) */
} TEapWscPacketHeader;

/* TLV header */
typedef struct {
    u16 attributeType;
    u16 dataLength;
} TTlvHeader;


/* process message methods */
/* Field verification. Returns the position of the field' value in the msg buffer.*/
static u8* EapWsc_ParseField(bufferObj *pInMsg, u16 theType, u32 minDataSize, u32 maxDataSize, u8 complexed, int *dataLen) 
{
    /* Extracts the type and the length. Positions pos to point to the data */
	u16 len;
	u8 *pos;
	u32 remaining = bufferRemaining(pInMsg);
	u16 tmpType, InBufferType;

	pos = bufferPos(pInMsg);
	if (remaining < sizeof(TTlvHeader) + minDataSize)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseField: insufficient buffer size");
        return NULL;
	}

	memcpy(&InBufferType, pos, sizeof(u16));

	tmpType = ntohs(InBufferType);
	if (theType != tmpType) 
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseField: unexpected type: %d", tmpType);
				return NULL;
			}

    pos += sizeof(u16); /* advance to length field */

	memcpy(&InBufferType, pos, sizeof(u16));

	len = ntohs(InBufferType);

    if (minDataSize > len)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseField: length field of type %d is too small", theType);
        return NULL;
	}
    if (maxDataSize && (len > maxDataSize))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseField: length field of type %d is greater than expected", theType);
        return NULL;
	}

    if (len + sizeof(TTlvHeader) > remaining)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseField: buffer overflow error");
        return NULL;
	}
    
    pos += sizeof(u16); /* advance to data field */
	if (complexed)
	{
		bufferAdvance(pInMsg, 2 * sizeof(u16));
	}
	else
	{
		bufferAdvance(pInMsg, 2 * sizeof(u16) + len);
	}

	if (dataLen)
	{
		*dataLen = len; /* return the field data length */
	}

	return pos; /* holds the current position (of the fields' value) */
}

static u32 EapWsc_ParseValue8(bufferObj *pInMsg, u16 theType, u8 *value) 
{
	u32 minDataSize = sizeof(u8);
	u8 *valuePos;
	
	valuePos = NULL;

	valuePos = EapWsc_ParseField(pInMsg, theType, minDataSize, 0, 0, NULL);
	if (valuePos == NULL)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseValue8: Invalid field of type: %d", theType);
		return NOK;
	}

	/* The specific Tlv Object */
    *value = *(u8 *)valuePos;
	
	return OK;
}

static u32 EapWsc_ParseValue16(bufferObj *pInMsg, u16 theType, u16 *value) 
{
	u32 minDataSize = sizeof(u16);
	u8 *valuePos;

	valuePos = NULL;

	valuePos = EapWsc_ParseField(pInMsg, theType, minDataSize, 0, 0, NULL);
	if (valuePos == NULL)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseValue16: Invalid field of type: %d", theType);
		return NOK;
	}

	/* The specific Tlv Object */
    memcpy(value, valuePos, 2);
	*value = ntohs(*value);

	return OK;
}

static u32 EapWsc_ParseValue32(bufferObj *pInMsg, u16 theType, u32 *value) 
{
	u32 minDataSize = sizeof(u32);
	u8 *valuePos;
	valuePos = NULL;

	valuePos = EapWsc_ParseField(pInMsg, theType, minDataSize, 0, 0, NULL);
	if (valuePos == NULL)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseValue32: Invalid field of type: %d", theType);
		return NOK;
	}

	/* The specific Tlv Object */
	memcpy(value, valuePos, 4);
	*value = ntohl(*value);
	
	return OK;
}

static u32 EapWsc_ParseValuePtr(bufferObj *pInMsg, u16 theType, u32 maxDataSize, TLVPUINT8 *value) 
{
	u32 minDataSize = 0;
	u8 *valuePos;

	valuePos = NULL;

	valuePos = EapWsc_ParseField(pInMsg, theType, minDataSize, maxDataSize, 0, &(value->length));
	if (valuePos == NULL)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseValuePtr: Invalid field of type: %d", theType);
		return NOK;
	}

	/* The specific Tlv Object - return the pointer itself */
    value->pValue = (u8 *)valuePos;
	
	return OK;
}

static u32 EapWsc_ParseCharPtr(bufferObj *pInMsg, u16 theType, u32 maxDataSize, TLVPCHAR *value)
{
	u32 minDataSize = 0;
	u8 *valuePos;
	
	valuePos = NULL;

	valuePos = EapWsc_ParseField(pInMsg, theType, minDataSize, maxDataSize, 0, &(value->length));
	if (valuePos == NULL)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ParseCharPtr: Invalid field of type: %d", theType);
		return NOK;
	}

	/* The specific Tlv Object - return the pointer itself */
    value->pValue = (char *)valuePos;
	
	return OK;
}

static void EapWsc_FreeEncryptSettings(TEapWsc *pEapWsc)
{
	int i;
	if(pEapWsc->pStaEncryptSettings)
	{
		if(pEapWsc->pStaEncryptSettings->credential.ssid.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->credential.ssid.pValue);			
		}

		for (i=0; i<MAX_NETWORK_KEY_NUM; i++)
		{
			if(pEapWsc->pStaEncryptSettings->credential.nwKey[i].pValue)
		{
				free(pEapWsc->pStaEncryptSettings->credential.nwKey[i].pValue);
			}
		}
		if(pEapWsc->pStaEncryptSettings->credential.macAddr.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->credential.macAddr.pValue);			
		}
		if(pEapWsc->pStaEncryptSettings->credential.eapType.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->credential.eapType.pValue);
		}
		if(pEapWsc->pStaEncryptSettings->credential.eapIdentity.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->credential.eapIdentity.pValue);
		}
		if(pEapWsc->pStaEncryptSettings->credential.rekeyKey.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->credential.rekeyKey.pValue);
		}
		if(pEapWsc->pStaEncryptSettings->credential.x509Cert.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->credential.x509Cert.pValue);
		}
		if(pEapWsc->pStaEncryptSettings->new_pwd.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->new_pwd.pValue);
		}
		if(pEapWsc->pStaEncryptSettings->keyWrapAuth.pValue)
		{
			free(pEapWsc->pStaEncryptSettings->keyWrapAuth.pValue);
		}

		free(pEapWsc->pStaEncryptSettings);
	}
	
}

static u32 EapWsc_BuildMsgAck(TEapWsc *pEapWsc, bufferObj* pOutMsg)
{
	u8 msgType = WSC_ID_MESSAGE_ACK;

	/* create Msg */
	bufferCreateChunk(pOutMsg);

	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, pOutMsg, SIZE_VERSION, &(pEapWsc->pWscSupplicantConfig->version));

	/* u8 msgType */
	wsc_supplicant_SerializeField(WSC_ID_MSG_TYPE, pOutMsg, SIZE_MSG_TYPE, &msgType);

	/* u8 *enrolleeNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_ENROLLEE_NONCE, pOutMsg, SIZE_ENROLLEE_NONCE, pEapWsc->enrolleeNonce);

	/* u8 *registrarNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_REGISTRAR_NONCE, pOutMsg, SIZE_REGISTRAR_NONCE, pEapWsc->registrarNonce);

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_BuildMsgAck: built %d byte message", bufferLength(pOutMsg));

	return OK;
}

static u32 EapWsc_BuildMsgM1(TEapWsc *pEapWsc, bufferObj* pOutMsg)
{
	u8 msgType = WSC_ID_MESSAGE_M1;
	int len;

    /* First generate/gather all the required data.*/

    /* Enrollee nonce N1 (openssl-generated) */
    RAND_bytes(pEapWsc->enrolleeNonce, SIZE_128_BITS);

    if(!pEapWsc->DHSecret)
    {
        if (cipherGenerateDHKeyPair(&pEapWsc->DHSecret) != OK)
		{
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM1: Failure in cipherGenerateDHKeyPair.");
			return NOK;
		}
    }

    /* Extract the DH public key */
    len = BN_bn2bin(pEapWsc->DHSecret->pub_key, pEapWsc->pke);
    if (len == 0)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM1: Failure in BN_bn2bin: %s", ERR_error_string(ERR_get_error(), NULL));
        return NOK;
    }

	/* create Msg */
	bufferCreateChunk(pOutMsg);

    /* Now start composing the message */

	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, pOutMsg, SIZE_VERSION, &(pEapWsc->pWscSupplicantConfig->version));

	/* u8 msgType */
	wsc_supplicant_SerializeField(WSC_ID_MSG_TYPE, pOutMsg, SIZE_MSG_TYPE, &msgType);

	/* u8 *uuid ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_UUID_E, pOutMsg, SIZE_UUID, pEapWsc->pWscSupplicantConfig->uuidE);

	/* u8 *macAddr; 6B */
	wsc_supplicant_SerializeField(WSC_ID_MAC_ADDR, pOutMsg, ETH_ALEN, pEapWsc->pWscSupplicantConfig->macAddress);

	/* u8 *enrolleeNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_ENROLLEE_NONCE, pOutMsg, SIZE_ENROLLEE_NONCE, pEapWsc->enrolleeNonce);

	/* u8 *publicKey ;192B */
	wsc_supplicant_SerializeField(WSC_ID_PUBLIC_KEY, pOutMsg, SIZE_PUB_KEY, pEapWsc->pke);

	/* u16 authTypeFlags */
	wsc_supplicant_SerializeField(WSC_ID_AUTH_TYPE_FLAGS, pOutMsg, SIZE_AUTH_TYPE_FLAGS, (u8 *)&(pEapWsc->pWscSupplicantConfig->authenticationTypeFlags));

	/* u16 encryptionTypeFlags */
	wsc_supplicant_SerializeField(WSC_ID_ENCR_TYPE_FLAGS, pOutMsg, SIZE_ENCR_TYPE_FLAGS, (u8 *)&(pEapWsc->pWscSupplicantConfig->encryptionTypeFlags));

	/* u8 connectionTypeFlags */
	wsc_supplicant_SerializeField(WSC_ID_CONN_TYPE_FLAGS, pOutMsg, SIZE_CONN_TYPE_FLAGS, &(pEapWsc->pWscSupplicantConfig->connectionTypeFlags));

	/* u16 configMethods */
	wsc_supplicant_SerializeField(WSC_ID_CONFIG_METHODS, pOutMsg, SIZE_CONFIG_METHODS, (u8 *)&(pEapWsc->pWscSupplicantConfig->configMethods));

	/* u8 state */
	wsc_supplicant_SerializeField(WSC_ID_SC_STATE, pOutMsg, SIZE_SC_STATE, &(pEapWsc->pWscSupplicantConfig->state));

	/* char *manufacturer; 64B */
	wsc_supplicant_SerializeField(WSC_ID_MANUFACTURER, pOutMsg, SIZE_MANUFACTURER, (u8 *)pEapWsc->pWscSupplicantConfig->manufacturer); /* although it has max. 64B */

	/* char *modelName; 32B */
	wsc_supplicant_SerializeField(WSC_ID_MODEL_NAME, pOutMsg, SIZE_MODEL_NAME, (u8 *)pEapWsc->pWscSupplicantConfig->modelName);

	/* char *modelNumber; 32B */
	wsc_supplicant_SerializeField(WSC_ID_MODEL_NUMBER, pOutMsg, SIZE_MODEL_NUMBER, (u8 *)pEapWsc->pWscSupplicantConfig->modelNumber);

	/* char *serialNumber; 32B */
	wsc_supplicant_SerializeField(WSC_ID_SERIAL_NUM, pOutMsg, SIZE_SERIAL_NUMBER, (u8 *)pEapWsc->pWscSupplicantConfig->serialNumber);

	/* sc_device_type_t primaryDeviceType; 8B */
	wsc_supplicant_SerializeHeader(WSC_ID_PRIM_DEV_TYPE, SIZE_PRIM_DEV_TYPE, pOutMsg);
	bufferAppend(pOutMsg, SIZE_PRIM_DEV_CAT_ID, (u8 *)&(pEapWsc->pWscSupplicantConfig->primaryDeviceType.category_id));
	bufferAppend(pOutMsg, SIZE_PRIM_DEV_OUI, (u8 *)&(pEapWsc->pWscSupplicantConfig->primaryDeviceType.oui));
	bufferAppend(pOutMsg, SIZE_PRIM_DEV_SUB_CAT_ID, (u8 *)&(pEapWsc->pWscSupplicantConfig->primaryDeviceType.sub_category_id));

	/* char *deviceName; 32B */
	wsc_supplicant_SerializeField(WSC_ID_DEVICE_NAME, pOutMsg, SIZE_DEVICE_NAME, (u8 *)pEapWsc->pWscSupplicantConfig->deviceName);

	/* u8 rfBand */
	wsc_supplicant_SerializeField(WSC_ID_RF_BAND, pOutMsg, SIZE_RF_BAND, &(pEapWsc->pWscSupplicantConfig->rfBand));

	/* u16 assocState */
	wsc_supplicant_SerializeField(WSC_ID_ASSOC_STATE, pOutMsg, SIZE_ASSOC_STATE, (u8 *)&(pEapWsc->pWscSupplicantConfig->assocState));

	/* u16 devicePasswordId */
	wsc_supplicant_SerializeField(WSC_ID_DEVICE_PWD_ID, pOutMsg, SIZE_DEVICE_PWD_ID, (u8 *)&(pEapWsc->pWscSupplicantConfig->devicePasswordId));

	/* u16 configError */
	wsc_supplicant_SerializeField(WSC_ID_CONFIG_ERROR, pOutMsg, SIZE_CONFIG_ERROR, (u8 *)&(pEapWsc->pWscSupplicantConfig->configError));

	/* u32 osVersion */
	wsc_supplicant_SerializeField(WSC_ID_OS_VERSION, pOutMsg, SIZE_OS_VERSION, (u8 *)&(pEapWsc->pWscSupplicantConfig->osVersion));

    /* skip optional attributes */

	/* Store the outgoing message */
	bufferReset(&(pEapWsc->OutMsg));
	bufferAppend(&(pEapWsc->OutMsg), bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

	
	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_BuildMsgM1: built %d byte message", bufferLength(pOutMsg));

	return OK;
}

static u32 EapWsc_ProcessMsgM2D(TEapWsc *pEapWsc, bufferObj* pInMsg)
{
	u8 version;
	u8 msgType;
	TLVPUINT8 tmpLVPUINT8;
	TLVPCHAR tmpLVPCHAR;
	u8 *tmpPos;
	u16 TempInBuffer;

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_ProcessMsgM2D: EapWsc_ProcessMsgM2D of %d byte message", bufferLength(pInMsg));

	/* First and foremost, check the version and message number.*/
	/* Don't deserialize (parse) incompatible messages! */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, &msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}

	/* u8 *enrolleeNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_ENROLLEE_NONCE, MAX_ENROLLEE_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_ENROLLEE_NONCE);
		return NOK;
	}

	/* confirm the enrollee nonce */
	if (memcmp(pEapWsc->enrolleeNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Incorrect enrollee nonce received");
		return NOK;
	}

	/* u8 *registrarNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_REGISTRAR_NONCE, MAX_REGISTRAR_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_REGISTRAR_NONCE);
		return NOK;
	}
    memcpy(pEapWsc->registrarNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

    /* First, check if we need to allocate peerDeviceInfo */
    if (!pEapWsc->pPeerDeviceInfo)
	{
		pEapWsc->pPeerDeviceInfo = malloc(sizeof(TEapWsc_DeviceInfo));
		if (pEapWsc->pPeerDeviceInfo == NULL)
		{
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to allocate memory (peerDeviceInfo)");
			return NOK;
		}
		memset(pEapWsc->pPeerDeviceInfo, 0, sizeof(TEapWsc_DeviceInfo));
	}

	/* u8 *uuid ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_UUID_R, MAX_UUID, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_UUID_R);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
    memcpy(pEapWsc->pPeerDeviceInfo->uuidR, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	/* u16 authTypeFlags */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_AUTH_TYPE_FLAGS, &(pEapWsc->pPeerDeviceInfo->authenticationTypeFlags)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_AUTH_TYPE_FLAGS);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}

	/* u16 encrTypeFlags */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_ENCR_TYPE_FLAGS, &(pEapWsc->pPeerDeviceInfo->encryptionTypeFlags)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_ENCR_TYPE_FLAGS);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
            
	/* u8 connectionTypeFlags */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_CONN_TYPE_FLAGS, &(pEapWsc->pPeerDeviceInfo->connectionTypeFlags)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_CONN_TYPE_FLAGS);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}

	/* u16 configMethods */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_CONFIG_METHODS, &(pEapWsc->pPeerDeviceInfo->configMethods)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_CONFIG_METHODS);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}

	/* char *manufacturer; 64B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_MANUFACTURER, MAX_MANUFACTURER, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_MANUFACTURER);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->manufacturer, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* char *modelName; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_MODEL_NAME, MAX_MODEL_NAME, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_MODEL_NAME);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->modelName, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* char *modelNumber; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_MODEL_NUMBER, MAX_MODEL_NUMBER, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_MODEL_NUMBER);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->modelNumber, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* char *serialNumber; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_SERIAL_NUM, MAX_SERIAL_NUMBER, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_SERIAL_NUM);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->serialNumber, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* sc_device_type_t primaryDeviceType; 8B */
	tmpPos = EapWsc_ParseField(pInMsg, WSC_ID_PRIM_DEV_TYPE, SIZE_PRIM_DEV_TYPE, 0, 1 /* complexed field */, NULL);
	memcpy(&pEapWsc->pPeerDeviceInfo->primaryDeviceType.category_id, tmpPos, SIZE_PRIM_DEV_CAT_ID);
    memcpy(&pEapWsc->pPeerDeviceInfo->primaryDeviceType.oui, bufferAdvance(pInMsg, SIZE_PRIM_DEV_CAT_ID), SIZE_PRIM_DEV_OUI);
    memcpy(&pEapWsc->pPeerDeviceInfo->primaryDeviceType.sub_category_id, bufferAdvance(pInMsg, SIZE_PRIM_DEV_OUI), SIZE_PRIM_DEV_SUB_CAT_ID);
    bufferAdvance(pInMsg, SIZE_PRIM_DEV_SUB_CAT_ID);

	/* char *deviceName; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_DEVICE_NAME, MAX_DEVICE_NAME, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_DEVICE_NAME);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->deviceName, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* u8 rfBand */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_RF_BAND, &(pEapWsc->pPeerDeviceInfo->rfBand)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_RF_BAND);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}

	/* u16 assocState */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_ASSOC_STATE, &(pEapWsc->pPeerDeviceInfo->assocState)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_ASSOC_STATE);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}

	/* u16 configError */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_CONFIG_ERROR, &(pEapWsc->pPeerDeviceInfo->configError)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_CONFIG_ERROR);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}
    
	/* u32 osVersion */
	if (EapWsc_ParseValue32(pInMsg, WSC_ID_OS_VERSION, &(pEapWsc->pPeerDeviceInfo->osVersion)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2D: Failed to parse field of type: %d", WSC_ID_OS_VERSION);
		free(pEapWsc->pPeerDeviceInfo);
		return NOK;
	}

	/* other attributes */
	while (bufferRemaining(pInMsg) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(pInMsg);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));

		switch (ntohs(TempInBuffer))
		{
			default:
				/* advance past the TLV */
				tmpPos += sizeof(u16); /* advance to length field */
				memcpy(&TempInBuffer, tmpPos, sizeof(u16));
				bufferAdvance(pInMsg, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}
	}

	/* Store the received buffer */
	bufferReset(&pEapWsc->InMsg);
	bufferAppend(&pEapWsc->InMsg, bufferLength(pInMsg), bufferGetBuf(pInMsg));  

	return OK;
}

static u32 EapWsc_ProcessMsgM2(TEapWsc *pEapWsc, bufferObj* pInMsg)
{
	u8 version;
	u8 msgType;
	TLVPUINT8 tmpLVPUINT8;
	TLVPCHAR tmpLVPCHAR;
	u8 *tmpPos;

	u8 secret[SIZE_PUB_KEY]; /* holds g^(AB) mod P */
	int secretLen = 0;
	u8 DHKey[SIZE_256_BITS];
	bufferObj kdkData;
    u8 kdk[SIZE_256_BITS];
    bufferObj kdkBuf;
    bufferObj personalString;
    bufferObj keys;
	bufferObj hmacData;
	u8 dataMac[BUF_SIZE_256_BITS];
	u16 TempInBuffer, tmpType;

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_ProcessMsgM2: EapWsc_ProcessMsgM2 of %d byte message", bufferLength(pInMsg));

	/* First and foremost, check the version and message number.*/
	/* Don't deserialize (parse) incompatible messages! */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, &msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}

	/* u8 *enrolleeNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_ENROLLEE_NONCE, MAX_ENROLLEE_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_ENROLLEE_NONCE);
		return NOK;
	}
	/* confirm the enrollee nonce */
	if (memcmp(pEapWsc->enrolleeNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Incorrect enrollee nonce received");
		return NOK;
	}

	/* u8 *registrarNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_REGISTRAR_NONCE, MAX_REGISTRAR_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_REGISTRAR_NONCE);
		return NOK;
	}
    memcpy(pEapWsc->registrarNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

    /* First, check if we need to allocate peerDeviceInfo */
    if (!pEapWsc->pPeerDeviceInfo)
	{
		pEapWsc->pPeerDeviceInfo = malloc(sizeof(TEapWsc_DeviceInfo));
		if (pEapWsc->pPeerDeviceInfo == NULL)
		{
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to allocate memory (peerDeviceInfo)");
			return NOK;
		}
		memset(pEapWsc->pPeerDeviceInfo, 0, sizeof(TEapWsc_DeviceInfo));
	}

	/* u8 *uuid ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_UUID_R, MAX_UUID, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_UUID_R);
		return NOK;
	}
    memcpy(pEapWsc->pPeerDeviceInfo->uuidR, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	/* u8 *publicKey ;192B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_PUBLIC_KEY, MAX_PUB_KEY, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_PUBLIC_KEY);
		return NOK;
	}
	/* read the registrar's public key */
    /* First store the raw public key (to be used for e/rhash computation) */
    memcpy(pEapWsc->pkr, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	/* u16 authTypeFlags */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_AUTH_TYPE_FLAGS, &(pEapWsc->pPeerDeviceInfo->authenticationTypeFlags)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_AUTH_TYPE_FLAGS);
		return NOK;
	}

	/* u16 encryptionTypeFlags */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_ENCR_TYPE_FLAGS, &(pEapWsc->pPeerDeviceInfo->encryptionTypeFlags)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_ENCR_TYPE_FLAGS);
		return NOK;
	}

	/* u8 connectionTypeFlags */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_CONN_TYPE_FLAGS, &(pEapWsc->pPeerDeviceInfo->connectionTypeFlags)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_CONN_TYPE_FLAGS);
		return NOK;
	}

	/* u16 configMethods */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_CONFIG_METHODS, &(pEapWsc->pPeerDeviceInfo->configMethods)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_CONFIG_METHODS);
		return NOK;
	}

	/* char *manufacturer; 64B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_MANUFACTURER, MAX_MANUFACTURER, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_MANUFACTURER);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->manufacturer, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* char *modelName; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_MODEL_NAME, MAX_MODEL_NAME, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_MODEL_NAME);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->modelName, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* char *modelNumber; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_MODEL_NUMBER, MAX_MODEL_NUMBER, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_MODEL_NUMBER);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->modelNumber, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* char *serialNumber; 32B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_SERIAL_NUM, MAX_SERIAL_NUMBER, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_SERIAL_NUM);
		return NOK;
	}
    memcpy(pEapWsc->pPeerDeviceInfo->serialNumber, tmpLVPUINT8.pValue, tmpLVPUINT8.length);
	pEapWsc->pPeerDeviceInfo->serialNumberLength = tmpLVPUINT8.length;

	/* sc_device_type_t primaryDeviceType; 8B */
	tmpPos = EapWsc_ParseField(pInMsg, WSC_ID_PRIM_DEV_TYPE, SIZE_PRIM_DEV_TYPE, 0, 1 /* complexed field */, NULL);
	memcpy(&pEapWsc->pPeerDeviceInfo->primaryDeviceType.category_id, tmpPos, SIZE_PRIM_DEV_CAT_ID);
    memcpy(&pEapWsc->pPeerDeviceInfo->primaryDeviceType.oui, bufferAdvance(pInMsg, SIZE_PRIM_DEV_CAT_ID), SIZE_PRIM_DEV_OUI);
    memcpy(&pEapWsc->pPeerDeviceInfo->primaryDeviceType.sub_category_id, bufferAdvance(pInMsg, SIZE_PRIM_DEV_OUI), SIZE_PRIM_DEV_SUB_CAT_ID);
    bufferAdvance(pInMsg, SIZE_PRIM_DEV_SUB_CAT_ID);

	/* char *deviceName; 32B */
	if (EapWsc_ParseCharPtr(pInMsg, WSC_ID_DEVICE_NAME, MAX_DEVICE_NAME, &tmpLVPCHAR) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_DEVICE_NAME);
		return NOK;
	}
	strncpy(pEapWsc->pPeerDeviceInfo->deviceName, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

	/* u8 rfBand */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_RF_BAND, &(pEapWsc->pPeerDeviceInfo->rfBand)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_RF_BAND);
		return NOK;
	}

	/* u16 assocState */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_ASSOC_STATE, &(pEapWsc->pPeerDeviceInfo->assocState)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_ASSOC_STATE);
		return NOK;
	}

	/* u16 configError */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_CONFIG_ERROR, &(pEapWsc->pPeerDeviceInfo->configError)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_CONFIG_ERROR);
		return NOK;
	}

	/* u16 devicePasswordId */
	if (EapWsc_ParseValue16(pInMsg, WSC_ID_DEVICE_PWD_ID, &(pEapWsc->pPeerDeviceInfo->devicePasswordId)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_DEVICE_PWD_ID);
		return NOK;
	}

	/* UINT32 osVersion */
	if (EapWsc_ParseValue32(pInMsg, WSC_ID_OS_VERSION, &(pEapWsc->pPeerDeviceInfo->osVersion)) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_OS_VERSION);
		return NOK;
	}

	/* other attributes */
	while (bufferRemaining(pInMsg) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(pInMsg);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		tmpType = ntohs(TempInBuffer);

		switch (tmpType)
		{
			case WSC_ID_AUTHENTICATOR:
				break;

			default:
				/* advance past the TLV */
				tmpPos += sizeof(u16); /* advance to length field */
				memcpy(&TempInBuffer, tmpPos, sizeof(u16));
				bufferAdvance(pInMsg, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}

		if (tmpType == WSC_ID_AUTHENTICATOR)
		{
			break;
		}
	}

	/* u8 *authenticator; 8B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_AUTHENTICATOR, MAX_AUTHENTICATOR, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to parse field of type: %d", WSC_ID_AUTHENTICATOR);
		return NOK;
	}
	/* tmpLVPUINT8.pValue, tmpLVPUINT8.length - contain authenticator info */

/*------------------------------------------------------------------------------*/

    /* to verify the hmac, we need to process the nonces, generate */
    /* the DH secret, the KDK and finally the auth key */

    /* Next, allocate memory for the pub key */
	pEapWsc->DH_PubKey_Peer = BN_new();
    if (!pEapWsc->DH_PubKey_Peer)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failed to allocate memory (DH_PubKey_Peer with BN_new())");
        return NOK;	
	}

    /* Finally, import the raw key into the bignum datastructure */
    if(BN_bin2bn(pEapWsc->pkr, SIZE_PUB_KEY, pEapWsc->DH_PubKey_Peer) == NULL)
    {
		BN_clear_free(pEapWsc->DH_PubKey_Peer);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: FAILED to produce a bignum for the PKr (BN_bin2bn())");
        return NOK;
    }

    /******* KDK generation *******/
    /* 1. generate the DH shared secret */

	/* Calculate g^(AB) mod P into secret[] */
    secretLen = DH_compute_key(secret, 
                           pEapWsc->DH_PubKey_Peer, /* g^(B) mod P */
                           pEapWsc->DHSecret); /* g^(A) mod P == DHSecret->PKe */

	BN_clear_free(pEapWsc->DH_PubKey_Peer);

    if (secretLen == -1)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Failure in DH_compute_key: %s", ERR_error_string(ERR_get_error(), NULL));
        return NOK;
    }        

    /* 2. compute the DHKey based on the DH secret */
    if (SHA256(secret, secretLen, DHKey) == NULL)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: SHA256 calculation failed");
        return NOK;
    }

    /* 3. Append the enrollee nonce(N1), enrollee mac and registrar nonce(N2) */
	bufferCreateEmpty(&kdkData, SIZE_128_BITS + MAC_ADDRESS_SIZE + SIZE_128_BITS);
    bufferAppend(&kdkData, SIZE_128_BITS, pEapWsc->enrolleeNonce);
    bufferAppend(&kdkData, ETH_ALEN, pEapWsc->pWscSupplicantConfig->macAddress);
    bufferAppend(&kdkData, SIZE_128_BITS, pEapWsc->registrarNonce);

    /* 4. now generate the KDK */
    if (HMAC(EVP_sha256(), DHKey, SIZE_256_BITS, bufferGetBuf(&kdkData), bufferLength(&kdkData), kdk, NULL) == NULL)
    {
		bufferFree(&kdkData);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Error generating KDK");
        return NOK;
    }

	bufferFree(&kdkData);
    /******* KDK generation *******/

    /******* Derivation of AuthKey, KeyWrapKey and EMSK *******/
    /* 1. initialize the appropriate buffer objects */
	bufferCreateFill(&kdkBuf, kdk, SIZE_256_BITS);
	bufferCreateFill(&personalString, (u8 *)PERSONALIZATION_STRING, strlen(PERSONALIZATION_STRING));
	bufferCreateEmpty(&keys, KDF_KEY_BITS/8); /* 640bit==80Byte */

    /* 2. call the key derivation function */
    cipherDeriveKey(&kdkBuf, &personalString, KDF_KEY_BITS, &keys);

	bufferFree(&kdkBuf);
	bufferFree(&personalString);

    /* 3. split the key into the component keys and store them */
    bufferRewindStart(&keys);

    bufferAppend(&(pEapWsc->authKey), SIZE_256_BITS, bufferPos(&keys));
    bufferAdvance(&keys, SIZE_256_BITS);

	bufferAppend(&(pEapWsc->keyWrapKey), SIZE_128_BITS, bufferPos(&keys));
    bufferAdvance(&keys, SIZE_128_BITS);

	/* EMSK is not currently used anywhere else -> this is currently redundant! */
	//bufferAppend(&(pEapWsc->emsk), SIZE_256_BITS, bufferPos(&keys));

	bufferFree(&keys);
    /******* Derivation of AuthKey, KeyWrapKey and EMSK *******/

    /******* HMAC validation *******/
    /* append the last message sent */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->OutMsg)), bufferLength(&(pEapWsc->OutMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->OutMsg)));

    /* append the current message. Don't append the last TLV (auth) */
	bufferAppend(&hmacData, 
				bufferLength(pInMsg)-(sizeof(TTlvHeader) + tmpLVPUINT8.length /* authenticator length */), 
				bufferGetBuf(pInMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), dataMac, NULL) == NULL)
    {
		bufferFree(&hmacData);
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

    /* next, compare it against the received hmac */
    if (memcmp(dataMac, tmpLVPUINT8.pValue, tmpLVPUINT8.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM2: HMAC validation failed");
        return NOK;
    }
    /******* HMAC validation *******/

    /* Store the received buffer */
	bufferReset(&pEapWsc->InMsg);
	bufferAppend(&pEapWsc->InMsg, bufferLength(pInMsg), bufferGetBuf(pInMsg));

	return OK;
}

static u32 EapWsc_BuildMsgM3(TEapWsc *pEapWsc, bufferObj* pOutMsg)
{
	u8 msgType = WSC_ID_MESSAGE_M3;
	bufferObj hmacData;
	u8 hmac[SIZE_256_BITS];
	u8 hashBuf[SIZE_256_BITS];
	bufferObj eHashBuf;
    
    /* First, generate or gather all the required data */

    /******* PSK1 and PSK2 generation *******/
    u8 *pwdPtr = pEapWsc->pWscSupplicantConfig->password;
    int pwdLen = strlen((char *)(pEapWsc->pWscSupplicantConfig->password));

    /* Hash 1st half of passwd. If it is an odd length, the extra byte */
    /* goes along with the first half */ 
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, pwdPtr, (pwdLen/2)+(pwdLen%2), hashBuf, NULL) == NULL)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM3: HMAC failed during PSK1 generation");
        return NOK;
    }
    /* copy first 128 bits into psk1 */
    memcpy(pEapWsc->psk1, hashBuf, SIZE_128_BITS);
    
    /* Hash 2nd half of password */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, pwdPtr + (pwdLen/2) + (pwdLen%2), (pwdLen/2), hashBuf, NULL) == NULL)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM3: HMAC failed during PSK2 generation");
        return NOK;
    }
    /* copy first 128 bits into psk2 */
    memcpy(pEapWsc->psk2, hashBuf, SIZE_128_BITS);
    /******* PSK1 and PSK2 generation *******/

    /******* EHash1 and EHash2 generation *******/
    RAND_bytes(pEapWsc->es1, SIZE_128_BITS);
    RAND_bytes(pEapWsc->es2, SIZE_128_BITS);
	

    /* Append the secret nonce 1(es1), PSK1, enrollee public key (pke) and registrar public key (pkr) */
	bufferCreateEmpty(&eHashBuf, SIZE_128_BITS + SIZE_128_BITS + SIZE_PUB_KEY + SIZE_PUB_KEY);
    bufferAppend(&eHashBuf, SIZE_128_BITS, pEapWsc->es1);
    bufferAppend(&eHashBuf, SIZE_128_BITS, pEapWsc->psk1);
    bufferAppend(&eHashBuf, SIZE_PUB_KEY, pEapWsc->pke);
    bufferAppend(&eHashBuf, SIZE_PUB_KEY, pEapWsc->pkr);

    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&eHashBuf), bufferLength(&eHashBuf), hashBuf, NULL) == NULL)
    {
		bufferFree(&eHashBuf);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM3: HMAC failed during EHash1 generation");
        return NOK;
    }
    memcpy(pEapWsc->eHash1, hashBuf, SIZE_256_BITS);

	/* Append the secret nonce 2(es2), PSK2, enrollee public key (pke) and registrar public key (pkr) */
	bufferReset(&eHashBuf);
    bufferAppend(&eHashBuf, SIZE_128_BITS, pEapWsc->es2);
    bufferAppend(&eHashBuf, SIZE_128_BITS, pEapWsc->psk2);
    bufferAppend(&eHashBuf, SIZE_PUB_KEY, pEapWsc->pke);
    bufferAppend(&eHashBuf, SIZE_PUB_KEY, pEapWsc->pkr);

    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&eHashBuf), bufferLength(&eHashBuf), hashBuf, NULL) == NULL)
    {
		bufferFree(&eHashBuf);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM3: HMAC failed during EHash2 generation");
        return NOK;
    }

	bufferFree(&eHashBuf);

    memcpy(pEapWsc->eHash2, hashBuf, SIZE_256_BITS);
    /******* EHash1 and EHash2 generation *******/

	/* create Msg */
	bufferCreateChunk(pOutMsg);
	
    /* Now assemble the message */
	
	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, pOutMsg, SIZE_VERSION, &(pEapWsc->pWscSupplicantConfig->version));

	/* u8 msgType */
	wsc_supplicant_SerializeField(WSC_ID_MSG_TYPE, pOutMsg, SIZE_MSG_TYPE, &msgType);

	/* u8 *registrarNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_REGISTRAR_NONCE, pOutMsg, SIZE_REGISTRAR_NONCE, pEapWsc->registrarNonce);

	/* u8 *eHash1 ;32B=256 bits */
	wsc_supplicant_SerializeField(WSC_ID_E_HASH1, pOutMsg, SIZE_E_HASH, pEapWsc->eHash1);

	/* u8 *eHash2 ;32B=256 bits */
	wsc_supplicant_SerializeField(WSC_ID_E_HASH2, pOutMsg, SIZE_E_HASH, pEapWsc->eHash2);

    /* No vendor extension */

	/* Calculate the hmac */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->InMsg)), bufferLength(&(pEapWsc->InMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->InMsg)));

    /* append the current message excluding the last TLV (auth) */
	bufferAppend(&hmacData, bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), hmac, NULL) == NULL)
    {
		bufferFree(&hmacData);
		bufferFree(pOutMsg);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM3: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

	/* u8 *authenticator; 8B */
	wsc_supplicant_SerializeField(WSC_ID_AUTHENTICATOR, pOutMsg, SIZE_AUTHENTICATOR, hmac);

	/* Store the outgoing message */
	bufferReset(&(pEapWsc->OutMsg));
	bufferAppend(&(pEapWsc->OutMsg), bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_BuildMsgM3: EapWsc_BuildMsgM3 built %d byte message", bufferLength(pOutMsg));

	return OK;
}

static u32 EapWsc_ProcessMsgM4(TEapWsc *pEapWsc, bufferObj* pInMsg)
{
	u8 version;
	u8 msgType;
	TLVPUINT8 tmpLVPUINT8, tmpLVPUINT8Auth;
	u8 *tmpPos;

	u8 *ip_encryptedData = NULL;
	int	encrSettingsLength = 0;
	u16 encrDataLength = 0;
	bufferObj cipherText, iv, plainText;

	bufferObj hmacData;
	u8 dataMac[BUF_SIZE_256_BITS];

	bufferObj rHashBuf;
	u8 hashBuf[SIZE_256_BITS];
	u16 TempInBuffer, tmpType;

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_ProcessMsgM4: EapWsc_ProcessMsgM4 of %d byte message", bufferLength(pInMsg));

	/* First and foremost, check the version and message number.*/
	/* Don't deserialize (parse) incompatible messages! */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, &msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}

	/* u8 *enrolleeNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_ENROLLEE_NONCE, MAX_ENROLLEE_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_ENROLLEE_NONCE);
		return NOK;
	}
	/* confirm the enrollee nonce */
	if (memcmp(pEapWsc->enrolleeNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Incorrect enrollee nonce received");
		return NOK;
	}

	/* u8 *rHash1; 32B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_R_HASH1, MAX_R_HASH, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_R_HASH1);
		return NOK;
	}
	memcpy(pEapWsc->rHash1, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	/* u8 *rHash2; 32B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_R_HASH2, MAX_R_HASH, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_R_HASH2);
		return NOK;
	}
	memcpy(pEapWsc->rHash2, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

    /* encrypted settings */
	tmpPos = bufferPos(pInMsg);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_ENCR_SETTINGS == ntohs(TempInBuffer))
    {
		/* Parse Encrypted Settings */
		/* parse the header first. Min data size of the IV + 1 block of data */
		tmpPos = EapWsc_ParseField(pInMsg, WSC_ID_ENCR_SETTINGS, (SIZE_ENCR_IV + ENCR_DATA_BLOCK_SIZE), 0, 1 /* complexed field */, &encrSettingsLength);
		bufferCreateFill(&iv, tmpPos, SIZE_ENCR_IV);
		ip_encryptedData = bufferAdvance(pInMsg, SIZE_ENCR_IV);
		encrDataLength = encrSettingsLength - SIZE_ENCR_IV;
		bufferAdvance(pInMsg, encrDataLength);
    }

	/* other attributes */
	while (bufferRemaining(pInMsg) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(pInMsg);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		tmpType = ntohs(TempInBuffer);

		switch (tmpType)
		{
			case WSC_ID_AUTHENTICATOR:
				break;

			default:

			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(pInMsg, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}

		if (tmpType == WSC_ID_AUTHENTICATOR)
		{
			break;
		}
	}

	/* u8 *authenticator; 8B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_AUTHENTICATOR, MAX_AUTHENTICATOR, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_AUTHENTICATOR);
		return NOK;
	}
	/* tmpLVPUINT8.pValue, tmpLVPUINT8.length - contain authenticator info */

    /******* HMAC validation *******/
    /* append the last message sent */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->OutMsg)), bufferLength(&(pEapWsc->OutMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->OutMsg)));

    /* append the current message. Don't append the last TLV (auth) */
	bufferAppend(&hmacData, 
				bufferLength(pInMsg)-(sizeof(TTlvHeader) + tmpLVPUINT8.length /* authenticator length */), 
				bufferGetBuf(pInMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), dataMac, NULL) == NULL)
    {
		bufferFree(&hmacData);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

    /* next, compare it against the received hmac */
    if (memcmp(dataMac, tmpLVPUINT8.pValue, tmpLVPUINT8.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: HMAC validation failed");
        return NOK;
    }
    /******* HMAC validation *******/

    /******* extract encrypted settings *******/
	bufferCreateFill(&cipherText, ip_encryptedData, encrDataLength);
	bufferCreateChunk(&plainText);

	cipherDecrypt(	&cipherText, 
					&iv,
					&pEapWsc->keyWrapKey, 
					&pEapWsc->authKey, 
					&plainText);

    bufferFree(&iv);
	bufferFree(&cipherText);

	bufferRewindStart(&plainText);

	/* Parse M4 Encrypted settings contained in plainText */

	/* u8 *rs1 ;16B=128 bits */
	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_R_SNONCE1, MAX_R_SNONCE, &tmpLVPUINT8) != OK)
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_R_SNONCE1);
		return NOK;
	}
	/* tmpLVPUINT8.pValue, tmpLVPUINT8.length - contain rs1 (Registrar Secret Nonce 1) info */

	/* other attributes */
	while (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		tmpType = ntohs(TempInBuffer);

		switch (tmpType)
		{
			case WSC_ID_KEY_WRAP_AUTH:
				break;

			default:

			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(&plainText, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}

		if (tmpType == WSC_ID_KEY_WRAP_AUTH)
		{
			break;
		}
	}

	/* u8 *KeyWrapAuthenticator */
	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_KEY_WRAP_AUTH, MAX_KEY_WRAP_AUTH, &tmpLVPUINT8Auth) != OK)
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Failed to parse field of type: %d", WSC_ID_KEY_WRAP_AUTH);
		return NOK;
	}
	/* tmpLVPUINT8Auth.pValue, tmpLVPUINT8Auth.length - contain Key Wrap authenticator info */

	/* validate the mac */

	/* calculate the hmac of the data (data only, not the last auth TLV) */
	if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&plainText), bufferLength(&plainText) - (sizeof(TTlvHeader) + tmpLVPUINT8Auth.length), dataMac, NULL) == NULL)
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Error generating HMAC of extracted encrypted settings");
		return NOK;
	}

	/* next, compare it against the received hmac */
	if (memcmp(dataMac, tmpLVPUINT8Auth.pValue, tmpLVPUINT8Auth.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Validation of encrypted settings HMAC - failed");
		return NOK;
	}

    /******* extract encrypted settings *******/

    /******* RHash1 validation *******/
    /* 1. Save RS1 */
    memcpy(pEapWsc->rs1, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	bufferFree(&plainText);

	/* 2. prepare the buffer */
	bufferCreateEmpty(&rHashBuf, SIZE_128_BITS + SIZE_128_BITS + SIZE_PUB_KEY + SIZE_PUB_KEY);
    bufferAppend(&rHashBuf, SIZE_128_BITS, pEapWsc->rs1);
    bufferAppend(&rHashBuf, SIZE_128_BITS, pEapWsc->psk1);
    bufferAppend(&rHashBuf, SIZE_PUB_KEY, pEapWsc->pke);
    bufferAppend(&rHashBuf, SIZE_PUB_KEY, pEapWsc->pkr);

    /* 3. generate the mac */
	if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&rHashBuf), bufferLength(&rHashBuf), hashBuf, NULL) == NULL)
	{
		bufferFree(&rHashBuf);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: Error generating HMAC for RHash1");
		return NOK;
	}

	bufferFree(&rHashBuf);

	/* 4. compare the mac to rhash1 */
    if (memcmp(pEapWsc->rHash1, hashBuf, SIZE_256_BITS) != 0)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM4: RHash1 HMAC validation failed");
        return NOK;
    }
    /******* RHash1 validation *******/

    /* Store the received buffer */
	bufferReset(&pEapWsc->InMsg);
	bufferAppend(&pEapWsc->InMsg, bufferLength(pInMsg), bufferGetBuf(pInMsg));

	return OK;
}

static u32 EapWsc_BuildMsgM5(TEapWsc *pEapWsc, bufferObj* pOutMsg)
{
	u8 msgType = WSC_ID_MESSAGE_M5;
	bufferObj cipherText, encData, iv;
	u8 tmpHmac[SIZE_256_BITS];

	bufferObj hmacData;
	u8 hmac[SIZE_256_BITS];

    /* First, generate or gather the required data */

	/* encrypted settings.*/
	bufferCreateEmpty(&encData, SIZE_192_BYTES);
	wsc_supplicant_SerializeField(WSC_ID_E_SNONCE1, &encData, SIZE_E_SNONCE, pEapWsc->es1);

	/* calculate the hmac and append the TLV to the buffer */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&encData), bufferLength(&encData), tmpHmac, NULL) == NULL)
    {
		bufferFree(&encData);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM5: Error generating HMAC");
        return NOK;
    }

	/* u8 *KeyWrapAuthenticator */
	wsc_supplicant_SerializeField(WSC_ID_KEY_WRAP_AUTH, &encData, SIZE_KEY_WRAP_AUTH, tmpHmac); /* Only the first 64 bits are sent */

	bufferCreateEmpty(&cipherText, SIZE_192_BYTES);
	bufferCreateEmpty(&iv, SIZE_ENCR_IV);

	cipherEncrypt(	&encData,
					&pEapWsc->keyWrapKey,
					&pEapWsc->authKey, 
					&cipherText, 
					&iv);

	bufferFree(&encData);

	/* create Msg */
	bufferCreateChunk(pOutMsg);

    /* Now assemble the message */

	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, pOutMsg, SIZE_VERSION, &(pEapWsc->pWscSupplicantConfig->version));

	/* u8 msgType */
	wsc_supplicant_SerializeField(WSC_ID_MSG_TYPE, pOutMsg, SIZE_MSG_TYPE, &msgType);

	/* u8 *registrarNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_REGISTRAR_NONCE, pOutMsg, SIZE_REGISTRAR_NONCE, pEapWsc->registrarNonce);

	/* encryption settings */
	wsc_supplicant_SerializeHeader(WSC_ID_ENCR_SETTINGS, (u16)(SIZE_ENCR_IV + bufferLength(&cipherText)), pOutMsg);
	bufferAppend(pOutMsg, SIZE_ENCR_IV, bufferGetBuf(&iv));
	bufferAppend(pOutMsg, bufferLength(&cipherText), bufferGetBuf(&cipherText));

	bufferFree(&iv);
	bufferFree(&cipherText);

	/* Calculate the hmac */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->InMsg)), bufferLength(&(pEapWsc->InMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->InMsg)));

    /* append the current message excluding the last TLV (auth) */
	bufferAppend(&hmacData, bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), hmac, NULL) == NULL)
    {
		bufferFree(&hmacData);
		bufferFree(pOutMsg);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM5: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

	/* u8 *authenticator; 8B */
	wsc_supplicant_SerializeField(WSC_ID_AUTHENTICATOR, pOutMsg, SIZE_AUTHENTICATOR, hmac);

	/* Store the outgoing message */
	bufferReset(&(pEapWsc->OutMsg));
	bufferAppend(&(pEapWsc->OutMsg), bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_BuildMsgM5: EapWsc_BuildMsgM5 built %d byte message", bufferLength(pOutMsg));

	return OK;
}

static u32 EapWsc_ProcessMsgM6(TEapWsc *pEapWsc, bufferObj* pInMsg)
{
	u8 version;
	u8 msgType;
	TLVPUINT8 tmpLVPUINT8, tmpLVPUINT8Auth;
	u8 *tmpPos;

	u8 *ip_encryptedData = NULL;
	int	encrSettingsLength = 0;
	u16 encrDataLength = 0;
	bufferObj cipherText, iv, plainText;

	bufferObj hmacData;
	u8 dataMac[BUF_SIZE_256_BITS];

	bufferObj rHashBuf;
	u8 hashBuf[SIZE_256_BITS];
	u16 TempInBuffer, tmpType;

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_ProcessMsgM6: EapWsc_ProcessMsgM6 of %d byte message", bufferLength(pInMsg));

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, &msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}

	/* u8 *enrolleeNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_ENROLLEE_NONCE, MAX_ENROLLEE_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Failed to parse field of type: %d", WSC_ID_ENROLLEE_NONCE);
		return NOK;
	}
	/* confirm the enrollee nonce */
	if (memcmp(pEapWsc->enrolleeNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Incorrect enrollee nonce received");
		return NOK;
	}

    /* encrypted settings */
	tmpPos = bufferPos(pInMsg);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_ENCR_SETTINGS == ntohs(TempInBuffer))
    {
		/* Parse Encrypted Settings */
		/* parse the header first. Min data size of the IV + 1 block of data */
		tmpPos = EapWsc_ParseField(pInMsg, WSC_ID_ENCR_SETTINGS, (SIZE_ENCR_IV + ENCR_DATA_BLOCK_SIZE), 0, 1 /* complexed field */, &encrSettingsLength);
		bufferCreateFill(&iv, tmpPos, SIZE_ENCR_IV);
		ip_encryptedData = bufferAdvance(pInMsg, SIZE_ENCR_IV);
		encrDataLength = encrSettingsLength - SIZE_ENCR_IV;
		bufferAdvance(pInMsg, encrDataLength);
    }

	/* other attributes */
	while (bufferRemaining(pInMsg) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(pInMsg);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		tmpType = ntohs(TempInBuffer);

		switch (tmpType)
		{
			case WSC_ID_AUTHENTICATOR:
				break;

			default:

			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(pInMsg, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}

		if (tmpType == WSC_ID_AUTHENTICATOR)
		{
			break;
		}
	}

	/* u8 *authenticator; 8B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_AUTHENTICATOR, MAX_AUTHENTICATOR, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Failed to parse field of type: %d", WSC_ID_AUTHENTICATOR);
		return NOK;
	}
    /* tmpLVPUINT8.pValue, tmpLVPUINT8.length - contain authenticator info */

    /******* HMAC validation *******/
    /* append the last message sent */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->OutMsg)), bufferLength(&(pEapWsc->OutMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->OutMsg)));

    /* append the current message. Don't append the last TLV (auth) */
	bufferAppend(&hmacData, 
				bufferLength(pInMsg)-(sizeof(TTlvHeader) + tmpLVPUINT8.length /* authenticator length */), 
				bufferGetBuf(pInMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), dataMac, NULL) == NULL)
    {
		bufferFree(&hmacData);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

    /* next, compare it against the received hmac */
    if (memcmp(dataMac, tmpLVPUINT8.pValue, tmpLVPUINT8.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: HMAC validation failed");
        return NOK;
    }
    /******* HMAC validation *******/

    /******* extract encrypted settings *******/
	bufferCreateFill(&cipherText, ip_encryptedData, encrDataLength);
	bufferCreateChunk(&plainText);

	cipherDecrypt(	&cipherText, 
					&iv,
					&pEapWsc->keyWrapKey, 
					&pEapWsc->authKey, 
					&plainText);

    bufferFree(&iv);
	bufferFree(&cipherText);

	bufferRewindStart(&plainText);

	/* Parse M6 Encrypted settings contained in plainText */

	/* u8 *rs2 ;16B=128 bits */
	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_R_SNONCE2, MAX_R_SNONCE, &tmpLVPUINT8) != OK)
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Failed to parse field of type: %d", WSC_ID_R_SNONCE2);
		return NOK;
	}
	/* tmpLVPUINT8.pValue, tmpLVPUINT8.length - contain rs2 (Registrar Secret Nonce 1) info */

	/* other attributes */
	while (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		tmpType = ntohs(TempInBuffer);

		switch (tmpType)
		{
			case WSC_ID_KEY_WRAP_AUTH:
				break;

			default:

			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(&plainText, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}

		if (tmpType == WSC_ID_KEY_WRAP_AUTH)
		{
			break;
		}
	}

	/* u8 *KeyWrapAuthenticator */
	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_KEY_WRAP_AUTH, MAX_KEY_WRAP_AUTH, &tmpLVPUINT8Auth) != OK)
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Failed to parse field of type: %d", WSC_ID_KEY_WRAP_AUTH);
		return NOK;
	}
	/* tmpLVPUINT8Auth.pValue, tmpLVPUINT8Auth.length - contain Key Wrap authenticator info */

	/* validate the mac */

	/* calculate the hmac of the data (data only, not the last auth TLV) */
	if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&plainText), bufferLength(&plainText) - (sizeof(TTlvHeader) + tmpLVPUINT8Auth.length), dataMac, NULL) == NULL)
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Error generating HMAC of extracted encrypted settings");
		return NOK;
	}

	/* next, compare it against the received hmac */
	if (memcmp(dataMac, tmpLVPUINT8Auth.pValue, tmpLVPUINT8Auth.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
	{
		bufferFree(&plainText);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Validation of encrypted settings HMAC - failed");
		return NOK;
	}
    /******* extract encrypted settings *******/

    /******* RHash2 validation *******/
    /* 1. Save RS2 */
	memcpy(pEapWsc->rs2, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	bufferFree(&plainText);

	/* 2. prepare the buffer */
	bufferCreateEmpty(&rHashBuf, SIZE_128_BITS + SIZE_128_BITS + SIZE_PUB_KEY + SIZE_PUB_KEY);
	bufferAppend(&rHashBuf, SIZE_128_BITS, pEapWsc->rs2);
	bufferAppend(&rHashBuf, SIZE_128_BITS, pEapWsc->psk2);
	bufferAppend(&rHashBuf, SIZE_PUB_KEY, pEapWsc->pke);
	bufferAppend(&rHashBuf, SIZE_PUB_KEY, pEapWsc->pkr);

	/* 3. generate the mac */
	if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&rHashBuf), bufferLength(&rHashBuf), hashBuf, NULL) == NULL)
	{
		bufferFree(&rHashBuf);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: Error generating HMAC for RHash2");
		return NOK;
	}

	bufferFree(&rHashBuf);

    /* 4. compare the mac to rhash2 */
	if (memcmp(pEapWsc->rHash2, hashBuf, SIZE_256_BITS) != 0)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM6: RHash2 HMAC validation failed");
		return NOK;
	}
    /******* RHash2 validation *******/

    /* Store the received buffer */
	bufferReset(&pEapWsc->InMsg);
	bufferAppend(&pEapWsc->InMsg, bufferLength(pInMsg), bufferGetBuf(pInMsg));

	return OK;
}

static u32 EapWsc_BuildMsgM7(TEapWsc *pEapWsc, bufferObj* pOutMsg)
{
	u8 msgType = WSC_ID_MESSAGE_M7;

	bufferObj cipherText, esBuf, iv;
	u8 tmpHmac[SIZE_256_BITS];

	bufferObj hmacData;
	u8 hmac[SIZE_256_BITS];

    /* First, generate or gather the required data */

	/* encrypted settings.*/
	bufferCreateEmpty(&esBuf, SIZE_192_BYTES);
	wsc_supplicant_SerializeField(WSC_ID_E_SNONCE2, &esBuf, SIZE_E_SNONCE, pEapWsc->es2);

	/* calculate the hmac and append the TLV to the buffer */
	if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&esBuf), bufferLength(&esBuf), tmpHmac, NULL) == NULL)
	{
		bufferFree(&esBuf);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM7: Error generating HMAC");
		return NOK;
	}

	/* u8 *KeyWrapAuthenticator */
	wsc_supplicant_SerializeField(WSC_ID_KEY_WRAP_AUTH, &esBuf, SIZE_KEY_WRAP_AUTH, tmpHmac); /* Only the first 64 bits are sent */

	bufferCreateEmpty(&cipherText, SIZE_192_BYTES);
	bufferCreateEmpty(&iv, SIZE_ENCR_IV);

	cipherEncrypt(	&esBuf,
					&pEapWsc->keyWrapKey,
					&pEapWsc->authKey, 
					&cipherText, 
					&iv);

	bufferFree(&esBuf);

	/* create Msg */
	bufferCreateChunk(pOutMsg);

    /* Now assemble the message */

	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, pOutMsg, SIZE_VERSION, &(pEapWsc->pWscSupplicantConfig->version));

	/* u8 msgType */
	wsc_supplicant_SerializeField(WSC_ID_MSG_TYPE, pOutMsg, SIZE_MSG_TYPE, &msgType);

	/* u8 *registrarNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_REGISTRAR_NONCE, pOutMsg, SIZE_REGISTRAR_NONCE, pEapWsc->registrarNonce);

	/* encryption settings */
	wsc_supplicant_SerializeHeader(WSC_ID_ENCR_SETTINGS, (u16)(SIZE_ENCR_IV + bufferLength(&cipherText)), pOutMsg);
	bufferAppend(pOutMsg, SIZE_ENCR_IV, bufferGetBuf(&iv));
	bufferAppend(pOutMsg, bufferLength(&cipherText), bufferGetBuf(&cipherText));

	bufferFree(&iv);
	bufferFree(&cipherText);

	/* Calculate the hmac */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->InMsg)), bufferLength(&(pEapWsc->InMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->InMsg)));

    /* append the current message excluding the last TLV (auth) */
	bufferAppend(&hmacData, bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), hmac, NULL) == NULL)
    {
		bufferFree(&hmacData);
		bufferFree(pOutMsg);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_BuildMsgM7: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

	/* u8 *authenticator; 8B */
	wsc_supplicant_SerializeField(WSC_ID_AUTHENTICATOR, pOutMsg, SIZE_AUTHENTICATOR, hmac);

	/* Store the outgoing message */
	bufferReset(&(pEapWsc->OutMsg));
	bufferAppend(&(pEapWsc->OutMsg), bufferLength(pOutMsg), bufferGetBuf(pOutMsg));

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_BuildMsgM7: EapWsc_BuildMsgM7 built %d byte message", bufferLength(pOutMsg));

	return OK;
}

static u32 EapWsc_ProcessMsgM8(TEapWsc *pEapWsc, bufferObj* pInMsg)
{
	u8 version;
	u8 msgType;
	TLVPUINT8 tmpLVPUINT8, tmpLVPUINT8Auth;
	TLVPCHAR tmpLVPCHAR;
	u8 *tmpPos;

	u8 *ip_encryptedData = NULL;
	int	encrSettingsLength = 0;
	u16 encrDataLength = 0;
	bufferObj cipherText, iv, plainText;

	bufferObj hmacData;
	u8 dataMac[BUF_SIZE_256_BITS];

	int	StaEncrSettingsLength;
	u16 TempInBuffer, tmpType;

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_ProcessMsgM8: EapWsc_ProcessMsgM8 of %d byte message", bufferLength(pInMsg));

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, &msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}
	
	/* u8 *enrolleeNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_ENROLLEE_NONCE, MAX_ENROLLEE_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_ENROLLEE_NONCE);
		return NOK;
	}
	/* confirm the enrollee nonce */
	if (memcmp(pEapWsc->enrolleeNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Incorrect enrollee nonce received");
		return NOK;
	}

    /* encrypted settings */
	tmpPos = bufferPos(pInMsg);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_ENCR_SETTINGS == ntohs(TempInBuffer))
    {
		/* Parse Encrypted Settings */
		/* parse the header first. Min data size of the IV + 1 block of data */
		tmpPos = EapWsc_ParseField(pInMsg, WSC_ID_ENCR_SETTINGS, (SIZE_ENCR_IV + ENCR_DATA_BLOCK_SIZE), 0, 1 /* complexed field */, &encrSettingsLength);
		bufferCreateFill(&iv, tmpPos, SIZE_ENCR_IV);
		ip_encryptedData = bufferAdvance(pInMsg, SIZE_ENCR_IV);
		encrDataLength = encrSettingsLength - SIZE_ENCR_IV;
		bufferAdvance(pInMsg, encrDataLength);
    }

	/* other attributes */
	while (bufferRemaining(pInMsg) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(pInMsg);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		tmpType = ntohs(TempInBuffer);

		switch (tmpType)
		{
			case WSC_ID_AUTHENTICATOR:
				break;

			default:

			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(pInMsg, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}

		if (tmpType == WSC_ID_AUTHENTICATOR)
		{
			break;
		}
	}

	/* u8 *authenticator; 8B */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_AUTHENTICATOR, MAX_AUTHENTICATOR, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_AUTHENTICATOR);
		return NOK;
	}
    /* tmpLVPUINT8.pValue, tmpLVPUINT8.length - contain authenticator info */

    /******* HMAC validation *******/
    /* append the last message sent */
	bufferCreateFill(&hmacData, bufferGetBuf(&(pEapWsc->OutMsg)), bufferLength(&(pEapWsc->OutMsg)));
	bufferAdvance(&hmacData, bufferLength(&(pEapWsc->OutMsg)));

    /* append the current message. Don't append the last TLV (auth) */
	bufferAppend(&hmacData, 
				bufferLength(pInMsg)-(sizeof(TTlvHeader) + tmpLVPUINT8.length /* authenticator length */), 
				bufferGetBuf(pInMsg));

    /* First calculate the hmac of the data */
    if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&hmacData), bufferLength(&hmacData), dataMac, NULL) == NULL)
    {
		bufferFree(&hmacData);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Error generating HMAC");
        return NOK;
    }

	bufferFree(&hmacData);

    /* next, compare it against the received hmac */
    if (memcmp(dataMac, tmpLVPUINT8.pValue, tmpLVPUINT8.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: HMAC validation failed");
        return NOK;
    }
    /******* HMAC validation *******/

	/******* extract encrypted settings *******/
	bufferCreateFill(&cipherText, ip_encryptedData, encrDataLength);
	bufferCreateChunk(&plainText);

	cipherDecrypt(	&cipherText, 
					&iv,
					&pEapWsc->keyWrapKey, 
					&pEapWsc->authKey, 
					&plainText);

    bufferFree(&iv);
	bufferFree(&cipherText);

	bufferRewindStart(&plainText);

	pEapWsc->pStaEncryptSettings = malloc(sizeof(TStaEncryptSettings));
	if (pEapWsc->pStaEncryptSettings == NULL)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (tlvEsM8Sta)");
		return NOK;
	}
	memset(pEapWsc->pStaEncryptSettings, 0, sizeof(TStaEncryptSettings));

	/* Parse 1st and only Credential settings */
	tmpPos = EapWsc_ParseField(&plainText, WSC_ID_CREDENTIAL, 0, 0, 1, &StaEncrSettingsLength);
	if (tmpPos == NULL)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Invalid field of type: %d", WSC_ID_CREDENTIAL);
		return NOK;
	}

	/* u8 nwIndex */
	if (EapWsc_ParseValue8(&plainText, WSC_ID_NW_INDEX, &(pEapWsc->pStaEncryptSettings->credential.nwIndex)) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_NW_INDEX);
		return NOK;
	}

	/* u8 *ssid ;32B=256 bits */
	pEapWsc->pStaEncryptSettings->credential.ssid.pValue = malloc(SIZE_32_BYTES);
	if (pEapWsc->pStaEncryptSettings->credential.ssid.pValue == NULL)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.ssid)");
		return NOK;
	}

	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_SSID, MAX_SSID, &tmpLVPUINT8) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_SSID);
		return NOK;
	}
	pEapWsc->pStaEncryptSettings->credential.ssid.length = tmpLVPUINT8.length;
	memcpy(pEapWsc->pStaEncryptSettings->credential.ssid.pValue, tmpLVPUINT8.pValue, tmpLVPUINT8.length);
	
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-WSC: EapWsc_ProcessMsgM8: ssid", pEapWsc->pStaEncryptSettings->credential.ssid.pValue, pEapWsc->pStaEncryptSettings->credential.ssid.length);		

	/* u16 authType */
	if (EapWsc_ParseValue16(&plainText, WSC_ID_AUTH_TYPE, &(pEapWsc->pStaEncryptSettings->credential.authType)) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_AUTH_TYPE);
		return NOK;
	}

	wpa_printf(MSG_INFO, "EAP-WSC: EapWsc_ProcessMsgM8: authType = %d",pEapWsc->pStaEncryptSettings->credential.authType);

	/* u16 encrType */
	if (EapWsc_ParseValue16(&plainText, WSC_ID_ENCR_TYPE, &(pEapWsc->pStaEncryptSettings->credential.encrType)) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_ENCR_TYPE);
		return NOK;
	}

	wpa_printf(MSG_INFO, "EAP-WSC: EapWsc_ProcessMsgM8: encrType = %d",pEapWsc->pStaEncryptSettings->credential.encrType);

    /* Parse optional network key index */
    pEapWsc->pStaEncryptSettings->credential.nwKeyIndex = DEFAULT_KEY_INDEX; /* According to spec - default network key index is 1 */

    tmpPos = bufferPos(&plainText);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_NW_KEY_INDEX == ntohs(TempInBuffer)) 
	{
		/* INT8 nwKeyIndex */
	    if (EapWsc_ParseValue8(&plainText, WSC_ID_NW_KEY_INDEX, &(pEapWsc->pStaEncryptSettings->credential.nwKeyIndex)) != OK)
	    {
			bufferFree(&plainText);
			EapWsc_FreeEncryptSettings(pEapWsc);
      
		    wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_NW_KEY_INDEX);
		    return NOK;
	    }
	}

	/* char *nwKey */
	pEapWsc->pStaEncryptSettings->credential.nwKey[pEapWsc->pStaEncryptSettings->credential.nwKeyIndex].pValue = malloc(SIZE_512_BITS+1);
	if (pEapWsc->pStaEncryptSettings->credential.nwKey[pEapWsc->pStaEncryptSettings->credential.nwKeyIndex].pValue == NULL)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.nwKey)");
		return NOK;
	}

	if (EapWsc_ParseCharPtr(&plainText, WSC_ID_NW_KEY, MAX_NW_KEY, &tmpLVPCHAR) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_NW_KEY);
		return NOK;
	}
	pEapWsc->pStaEncryptSettings->credential.nwKey[pEapWsc->pStaEncryptSettings->credential.nwKeyIndex].length = tmpLVPCHAR.length;
	memcpy(pEapWsc->pStaEncryptSettings->credential.nwKey[pEapWsc->pStaEncryptSettings->credential.nwKeyIndex].pValue, tmpLVPCHAR.pValue, tmpLVPCHAR.length);	

	if ((pEapWsc->pStaEncryptSettings->credential.authType & WSC_AUTHTYPE_WPAPSK) || (pEapWsc->pStaEncryptSettings->credential.authType & WSC_AUTHTYPE_WPA2PSK))
	{
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-WSC: EapWsc_ProcessMsgM8: nwKey", (u8 *)(pEapWsc->pStaEncryptSettings->credential.nwKey[pEapWsc->pStaEncryptSettings->credential.nwKeyIndex].pValue), pEapWsc->pStaEncryptSettings->credential.nwKey[pEapWsc->pStaEncryptSettings->credential.nwKeyIndex].length);
	}

   /* Eitan TO DO: Parse multiple network keys */

	/* u8 *macAddr; 6B */
	pEapWsc->pStaEncryptSettings->credential.macAddr.pValue = malloc(MAX_MAC_ADDR);
	if (pEapWsc->pStaEncryptSettings->credential.macAddr.pValue == NULL)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.macAddr)");
		return NOK;
	}
	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_MAC_ADDR, MAX_MAC_ADDR, &tmpLVPUINT8) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_MAC_ADDR);
		return NOK;
	}
	pEapWsc->pStaEncryptSettings->credential.macAddr.length = tmpLVPUINT8.length;
	memcpy(pEapWsc->pStaEncryptSettings->credential.macAddr.pValue, tmpLVPUINT8.pValue, tmpLVPUINT8.length);

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-WSC: EapWsc_ProcessMsgM8: macAddr", pEapWsc->pStaEncryptSettings->credential.macAddr.pValue, pEapWsc->pStaEncryptSettings->credential.macAddr.length);

	/* Parse optional attributes */

    /* 25/9/2006 - parse EAP_TYPE, KEY_PROVIDED_AUTOMATICALLY, IS_802_1_X_ENABLED and WEP_TRANSMIT_KEY TLVs */

    /* u8 *eapType */
    if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* Nothing is done with the parsed field at this stage */
		/* FOR FUTURE USE - handle field here */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		if (WSC_ID_EAP_TYPE == ntohs(TempInBuffer)) 
		{
			if (EapWsc_ParseValuePtr(&plainText, WSC_ID_EAP_TYPE, 0, &tmpLVPUINT8) != OK)
			{
				bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_EAP_TYPE);
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.eapType.pValue = malloc(tmpLVPUINT8.length);
			if (pEapWsc->pStaEncryptSettings->credential.eapType.pValue == NULL)
			{
				bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.eapIdentity)");
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.eapType.length = tmpLVPUINT8.length;
			memcpy(pEapWsc->pStaEncryptSettings->credential.eapType.pValue, tmpLVPUINT8.pValue, tmpLVPUINT8.length);
		}
	}

 	tmpPos = bufferPos(&plainText);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_KEY_PROVIDED_AUTO == ntohs(TempInBuffer)) 
	{
      /* u16 encrType */
      if (EapWsc_ParseValue8(&plainText, WSC_ID_KEY_PROVIDED_AUTO, &(pEapWsc->pStaEncryptSettings->credential.bKey_Provided_Automatically)) != OK)
      {
    	bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);
   		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_KEY_PROVIDED_AUTO);
   		return NOK;
      }
    }

    tmpPos = bufferPos(&plainText);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_802_1_X_ENABLED == ntohs(TempInBuffer)) 
	{
      /* u16 encrType */
      if (EapWsc_ParseValue8(&plainText, WSC_ID_802_1_X_ENABLED, &(pEapWsc->pStaEncryptSettings->credential.b_Is_802_1x_enabled)) != OK)
      {
    	bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);
   		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_802_1_X_ENABLED);
   		return NOK;
      }
    }

    tmpPos = bufferPos(&plainText);
	memcpy(&TempInBuffer, tmpPos, sizeof(u16));
	if (WSC_ID_WEP_TRANSMIT_KEY == ntohs(TempInBuffer)) 
	{
      /* u16 encrType */
      if (EapWsc_ParseValue8(&plainText, WSC_ID_WEP_TRANSMIT_KEY, &(pEapWsc->pStaEncryptSettings->credential.WEP_transmit_key)) != OK)
      {
    	bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);
   		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_WEP_TRANSMIT_KEY);
   		return NOK;
      }
    }

/* ------------------------------------------------------- */

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* u8 *eapIdentity */
		/* Nothing is done with the parsed field at this stage */
		/* FOR FUTURE USE - handle field here */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		if (WSC_ID_EAP_IDENTITY == ntohs(TempInBuffer)) 
		{
			if (EapWsc_ParseValuePtr(&plainText, WSC_ID_EAP_IDENTITY, 0, &tmpLVPUINT8) != OK)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_EAP_IDENTITY);
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.eapIdentity.pValue = malloc(tmpLVPUINT8.length);
			if (pEapWsc->pStaEncryptSettings->credential.eapIdentity.pValue == NULL)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.eapIdentity)");
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.eapIdentity.length = tmpLVPUINT8.length;
			memcpy(pEapWsc->pStaEncryptSettings->credential.eapIdentity.pValue, tmpLVPUINT8.pValue, tmpLVPUINT8.length);
		}
	}

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* UINT32 keyLifetime */
		/* Nothing is done with the parsed field at this stage */
		/* FOR FUTURE USE - handle field here */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		if (WSC_ID_KEY_LIFETIME == ntohs(TempInBuffer)) 
		{
			if (EapWsc_ParseValue32(&plainText, WSC_ID_KEY_LIFETIME, &(pEapWsc->pStaEncryptSettings->credential.keyLifetime)) != OK)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_KEY_LIFETIME);
				return NOK;
			}
		}
	}

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* void *vendorExt */
		/* skip vendor extension fields (there may be multiple TLVs) */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		while (WSC_ID_VENDOR_EXT == ntohs(TempInBuffer)) 
		{
			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(&plainText, sizeof(TTlvHeader) + ntohs(TempInBuffer));

			tmpPos = bufferPos(&plainText);
		}
	}

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* u8 *rekeyKey; 32B */
		/* Nothing is done with the parsed field at this stage */
		/* FOR FUTURE USE - handle field here */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		if (WSC_ID_REKEY_KEY == ntohs(TempInBuffer)) 
		{
			if (EapWsc_ParseValuePtr(&plainText, WSC_ID_REKEY_KEY, 0, &tmpLVPUINT8) != OK)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_REKEY_KEY);
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.rekeyKey.pValue = malloc(tmpLVPUINT8.length);
			if (pEapWsc->pStaEncryptSettings->credential.rekeyKey.pValue == NULL)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.eapIdentity)");
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.rekeyKey.length = tmpLVPUINT8.length;
			memcpy(pEapWsc->pStaEncryptSettings->credential.rekeyKey.pValue, tmpLVPUINT8.pValue, tmpLVPUINT8.length);
		}
	}

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* u8 *x509Cert */
		/* Nothing is done with the parsed field at this stage */
		/* FOR FUTURE USE - handle field here */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		if (WSC_ID_X509_CERT == ntohs(TempInBuffer)) 
		{
			if (EapWsc_ParseValuePtr(&plainText, WSC_ID_X509_CERT, 0, &tmpLVPUINT8) != OK)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_X509_CERT);
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.x509Cert.pValue = malloc(tmpLVPUINT8.length);
			if (pEapWsc->pStaEncryptSettings->credential.x509Cert.pValue == NULL)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (credential.x509Cert)");
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->credential.x509Cert.length = tmpLVPUINT8.length;
			memcpy(pEapWsc->pStaEncryptSettings->credential.x509Cert.pValue, tmpLVPUINT8.pValue, tmpLVPUINT8.length);
		}
	}

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		if (WSC_ID_NEW_PWD == ntohs(TempInBuffer)) 
		{
			/* If the New Password TLV is included, the Device password ID is required */
			/* char *new_pwd */
			pEapWsc->pStaEncryptSettings->new_pwd.pValue = malloc(SIZE_64_BYTES);
			if (pEapWsc->pStaEncryptSettings->new_pwd.pValue == NULL)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to allocate memory (tlvEsM8Sta.new_pwd)");
				return NOK;
			}
				if (EapWsc_ParseCharPtr(&plainText, WSC_ID_NEW_PWD, MAX_NEW_PWD, &tmpLVPCHAR) != OK)
			{
				bufferFree(&plainText);
				EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_NEW_PWD);
				return NOK;
			}
			pEapWsc->pStaEncryptSettings->new_pwd.length = tmpLVPCHAR.length;
			memcpy(pEapWsc->pStaEncryptSettings->new_pwd.pValue, tmpLVPCHAR.pValue, tmpLVPCHAR.length);

			/* u16 pwdId */
			if (EapWsc_ParseValue16(&plainText, WSC_ID_DEVICE_PWD_ID, &(pEapWsc->pStaEncryptSettings->pwdId)) != OK)
			{
				bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

				wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_DEVICE_PWD_ID);
				return NOK;
			}
		}
	}

	if (bufferRemaining(&plainText) >= sizeof(TTlvHeader))
	{
		/* skip vendor extension fields (There may be multiple TLVs) */
		tmpPos = bufferPos(&plainText);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		while ((WSC_ID_VENDOR_EXT == ntohs(TempInBuffer)) ||
                       (WSC_ID_RF_BAND == ntohs(TempInBuffer)))
		{
			/* advance past the TLV */
			tmpPos += sizeof(u16); /* advance to length field */
			memcpy(&TempInBuffer, tmpPos, sizeof(u16));
			bufferAdvance(&plainText, sizeof(TTlvHeader) + ntohs(TempInBuffer));

			tmpPos = bufferPos(&plainText);
                        memcpy(&TempInBuffer, tmpPos, sizeof(u16));
		}
	}

	/* u8 *KeyWrapAuthenticator */
	if (EapWsc_ParseValuePtr(&plainText, WSC_ID_KEY_WRAP_AUTH, MAX_KEY_WRAP_AUTH, &tmpLVPUINT8Auth) != OK)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Failed to parse field of type: %d", WSC_ID_KEY_WRAP_AUTH);
		return NOK;
	}
	/* tmpLVPUINT8Auth.pValue, tmpLVPUINT8Auth.length - contain Key Wrap authenticator info */

	/* validate the mac */

	/* calculate the hmac of the data (data only, not the last auth TLV) */
	if (HMAC(EVP_sha256(), bufferGetBuf(&(pEapWsc->authKey)), SIZE_256_BITS, bufferGetBuf(&plainText), bufferLength(&plainText) - (sizeof(TTlvHeader) + tmpLVPUINT8Auth.length), dataMac, NULL) == NULL)
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Error generating HMAC of extracted encrypted settings");
		return NOK;
	}

	/* next, compare it against the received hmac */
	if (memcmp(dataMac, tmpLVPUINT8Auth.pValue, tmpLVPUINT8Auth.length) != 0) /* tmpLVPUINT8 contains parsed authenticator info */
	{
		bufferFree(&plainText);
		EapWsc_FreeEncryptSettings(pEapWsc);

		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgM8: Validation of encrypted settings HMAC - failed");
		return NOK;
	}

	bufferFree(&plainText);
	
	/******* extract encrypted settings *******/

    /* Store the received buffer */
	bufferReset(&pEapWsc->InMsg);
	bufferAppend(&pEapWsc->InMsg, bufferLength(pInMsg), bufferGetBuf(pInMsg));

	return OK;
}

static u32 EapWsc_BuildMsgDone(TEapWsc *pEapWsc, bufferObj* pOutMsg)
{
	u8 msgType = WSC_ID_MESSAGE_DONE;

	/* create Msg */
	bufferCreateChunk(pOutMsg);

	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, pOutMsg, SIZE_VERSION, &(pEapWsc->pWscSupplicantConfig->version));

	/* u8 msgType */
	wsc_supplicant_SerializeField(WSC_ID_MSG_TYPE, pOutMsg, SIZE_MSG_TYPE, &msgType);

	/* u8 *enrolleeNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_ENROLLEE_NONCE, pOutMsg, SIZE_ENROLLEE_NONCE, pEapWsc->enrolleeNonce);

	/* u8 *registrarNonce ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_REGISTRAR_NONCE, pOutMsg, SIZE_REGISTRAR_NONCE, pEapWsc->registrarNonce);

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_BuildMsgDone: EapWsc_BuildMsgDone built %d byte message", bufferLength(pOutMsg));

	return OK;
}

static u32 EapWsc_ProcessMsgAck(TEapWsc *pEapWsc, bufferObj* pInMsg)
{
	u8 version;
	u8 msgType;
	TLVPUINT8 tmpLVPUINT8;
	u8 *tmpPos;
	u16 TempInBuffer;

	wpa_printf(MSG_INFO,"EAP-WSC: EapWsc_ProcessMsgAck: EapWsc_ProcessMsgAck of %d byte message", bufferLength(pInMsg));

	/* deserialize (parse) the message */
	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgAck: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, &msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgAck: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}

	/* u8 *enrolleeNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_ENROLLEE_NONCE, MAX_ENROLLEE_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgAck: Failed to parse field of type: %d", WSC_ID_ENROLLEE_NONCE);
		return NOK;
	}
	/* confirm the enrollee nonce */
	if (memcmp(pEapWsc->enrolleeNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgAck: Incorrect enrollee nonce received");
		return NOK;
	}

	/* u8 *registrarNonce ;16B=128 bits */
	if (EapWsc_ParseValuePtr(pInMsg, WSC_ID_REGISTRAR_NONCE, MAX_REGISTRAR_NONCE, &tmpLVPUINT8) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgAck: Failed to parse field of type: %d", WSC_ID_REGISTRAR_NONCE);
		return NOK;
	}

	/* confirm the registrar nonce */
	if (memcmp(pEapWsc->registrarNonce, tmpLVPUINT8.pValue, tmpLVPUINT8.length))
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_ProcessMsgAck: Incorrect registrar nonce received");
		return NOK;
	}

	/* other attributes */
	while (bufferRemaining(pInMsg) >= sizeof(TTlvHeader))
	{
		tmpPos = bufferPos(pInMsg);
		memcpy(&TempInBuffer, tmpPos, sizeof(u16));

		switch (ntohs(TempInBuffer))
		{
			default:

				/* advance past the TLV */
				tmpPos += sizeof(u16); /* advance to length field */
				memcpy(&TempInBuffer, tmpPos, sizeof(u16));
				bufferAdvance(pInMsg, sizeof(TTlvHeader) + ntohs(TempInBuffer));
				break;
		}
	}

	return OK;
}

static u32 EapWsc_GetMsgType(TEapWsc *pEapWsc, u8 *msgType, bufferObj* pInMsg)
{
	u8 version;
	*msgType = WSC_ID_MESSAGE_UNKNOWN;

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_VERSION, &version) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_GetMsgType: Failed to parse field of type: %d", WSC_ID_VERSION);
		return NOK;
	}

	if(version != pEapWsc->pWscSupplicantConfig->version) 
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_GetMsgType: SC Version specified (0x%x) is incompatible with LocalStationConfig SC version: 0x%x", version, pEapWsc->pWscSupplicantConfig->version);
		return NOK;
	}

	if (EapWsc_ParseValue8(pInMsg, WSC_ID_MSG_TYPE, msgType) != OK)
	{
		wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_GetMsgType: Failed to parse field of type: %d", WSC_ID_MSG_TYPE);
		return NOK;
	}

    bufferRewindStart(pInMsg);
	return OK;
}

static u32 EapWsc_HandleMsg(TEapWsc *pEapWsc, bufferObj* pInMsg, bufferObj* pOutMsg)
{
	u8 msgType = 0;
	
	switch (pEapWsc->LastMessageSent)
    {
		case WSC_ID_MESSAGE_UNKNOWN:

			if (OK != EapWsc_BuildMsgM1(pEapWsc, pOutMsg)) return NOK;
			pEapWsc->LastMessageSent = WSC_ID_MESSAGE_M1;
			break;
			
		case WSC_ID_MESSAGE_M1:

			if(OK != EapWsc_GetMsgType(pEapWsc, &msgType, pInMsg)) return NOK;

			switch(msgType)
			{
				case WSC_ID_MESSAGE_M2D:
					
					pEapWsc->LastMessageRecv = WSC_ID_MESSAGE_M2D;
					/* Process message M2D from the registrar */
					if(OK != EapWsc_ProcessMsgM2D(pEapWsc, pInMsg)) return NOK;					
					/* Send an ACK to the registrar */
					EapWsc_BuildMsgAck(pEapWsc, pOutMsg);					
					pEapWsc->LastMessageSent = WSC_ID_MESSAGE_ACK;
					break;
					
				case WSC_ID_MESSAGE_M2:

					pEapWsc->LastMessageRecv = WSC_ID_MESSAGE_M2;
					/* Process message M2 from the registrar */
					if (OK != EapWsc_ProcessMsgM2(pEapWsc, pInMsg)) return NOK;
					/* Send message M3 to the registrar */
					if (OK != EapWsc_BuildMsgM3(pEapWsc, pOutMsg)) return NOK;					
					pEapWsc->LastMessageSent = WSC_ID_MESSAGE_M3;
					break;
					
				default:
					wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_HandleMsg: WSC_ID_MESSAGE_M1 - Received wrong message type: %d", msgType);
				return NOK;
			}
			break;
			
		case WSC_ID_MESSAGE_M3:
			
			if(OK != EapWsc_GetMsgType(pEapWsc, &msgType, pInMsg)) return NOK;
			pEapWsc->LastMessageRecv = WSC_ID_MESSAGE_M4;
			/* Process message M4 from the registrar */
			if(OK != EapWsc_ProcessMsgM4(pEapWsc, pInMsg)) return NOK;
			/* Send message M5 to the registrar */
			if (OK != EapWsc_BuildMsgM5(pEapWsc, pOutMsg)) return NOK;					
			pEapWsc->LastMessageSent = WSC_ID_MESSAGE_M5;
			break;

		case WSC_ID_MESSAGE_M5:
			
			if(OK != EapWsc_GetMsgType(pEapWsc, &msgType, pInMsg)) return NOK;
			pEapWsc->LastMessageRecv = WSC_ID_MESSAGE_M6;
			/* Process message M6 from the registrar */
			if(OK != EapWsc_ProcessMsgM6(pEapWsc, pInMsg)) return NOK;
			/* Send message M7 to the registrar */
			if (OK != EapWsc_BuildMsgM7(pEapWsc, pOutMsg)) return NOK;					
			pEapWsc->LastMessageSent = WSC_ID_MESSAGE_M7;
			break;
		
		case WSC_ID_MESSAGE_M7:

			if(OK != EapWsc_GetMsgType(pEapWsc, &msgType, pInMsg)) return NOK;
			pEapWsc->LastMessageRecv = WSC_ID_MESSAGE_M8;
			/* Process message M8 from the registrar */
			if(OK != EapWsc_ProcessMsgM8(pEapWsc, pInMsg)) return NOK;

			/* Send message DONE to the registrar */
			if (OK != EapWsc_BuildMsgDone(pEapWsc, pOutMsg)) return NOK;					
			pEapWsc->LastMessageSent = WSC_ID_MESSAGE_DONE;

			pEapWsc->smState = EAP_WSC_STATE_SUCCESS;
			break;

		case WSC_ID_MESSAGE_DONE:

			if(OK != EapWsc_GetMsgType(pEapWsc, &msgType, pInMsg)) return NOK;
			pEapWsc->LastMessageRecv = WSC_ID_MESSAGE_ACK;
			/* Process message ACK from the registrar */
			if(OK != EapWsc_ProcessMsgAck(pEapWsc, pInMsg)) return NOK;

			break;

			}

	return OK;
	}

static void EapWsc_RestartSM(TEapWsc* pEapWsc)
{
	if(pEapWsc->DHSecret)
	{
		DH_free(pEapWsc->DHSecret);
		pEapWsc->DHSecret = NULL;
	}

	if(pEapWsc->pPeerDeviceInfo)
		free(pEapWsc->pPeerDeviceInfo);

	EapWsc_FreeEncryptSettings(pEapWsc);
	
	bufferFree(&(pEapWsc->keyWrapKey));
	bufferFree(&(pEapWsc->authKey));
	bufferFree(&(pEapWsc->InMsg));
	bufferFree(&(pEapWsc->OutMsg));

	free(pEapWsc);
}

static u32 EapWsc_CheckMsg(EEapWsc_SMState state, const u8 *reqData, size_t reqDataLen, TEapWscPacketHeader* hdr, struct eap_method_ret *ret)
{
	if(state == EAP_WSC_STATE_START)
	{
		if (!reqData || !reqDataLen || (hdr->opCode != WSC_Start))
        {
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_CheckMsg: Wrong input parameters");
			ret->ignore = TRUE;
			return NOK;
        }				
	}
	else
	{
		if(!reqData || !reqDataLen)
        {
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_CheckMsg: Wrong input parameters");
			ret->ignore = TRUE;
			return NOK;
        }

		wpa_printf(MSG_DEBUG,"EAP-WSC: EapWsc_CheckMsg: Received packet, Length = %lu", (unsigned long) reqDataLen);

        if((hdr->opCode < WSC_Start) || (hdr->opCode > WSC_Done))
        {
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_CheckMsg: Wrong OpCode received");
			ret->ignore = TRUE;
			return NOK;
        }

        if(hdr->flags & 0x02) 
        {
			wpa_printf(MSG_ERROR,"EAP-WSC: EapWsc_CheckMsg: First EAP Packet of a fragmented EAP Msg received, EAP fragmentation not supported.");
			ret->ignore = TRUE;
			return NOK;
        }        
	}	

	return OK;
}



static void * eap_wsc_init(struct eap_sm *sm)
{
	TEapWsc* pEapWsc;

    wpa_printf(MSG_INFO,"EAP-WSC: Entered eap_wsc_init");

    pEapWsc = malloc(sizeof(*pEapWsc));
    if (pEapWsc == NULL)
        return NULL;
    memset(pEapWsc, 0, sizeof(*pEapWsc));


    pEapWsc->smState = EAP_WSC_STATE_START;
	pEapWsc->LastMessageSent = WSC_ID_MESSAGE_UNKNOWN;
    pEapWsc->sm = sm;
	pEapWsc->pWscSupplicantConfig = wsc_supplicant_GetWscSupplicantConfig();
    

	pEapWsc->DH_PubKey_Peer = NULL;
	pEapWsc->DHSecret = NULL;
	pEapWsc->pPeerDeviceInfo = NULL;	

    return pEapWsc;
}


static void eap_wsc_deinit(struct eap_sm *sm, void *priv)
{
    wpa_printf(MSG_INFO,"EAP-WSC: Entered eap_wsc_deinit");
}


static u8 * eap_wsc_process(struct eap_sm *sm, void *priv,
			    struct eap_method_ret *ret,
			    const u8 *reqData, size_t reqDataLen,
			    size_t *respDataLen)
{
	u32 res;
	TEapWsc* pEapWsc = priv;
	TEapWscPacketHeader* hdr = (TEapWscPacketHeader*)reqData;
	bufferObj InMsg,OutMsg;
	u8* 					resp;
	TEapWscPacketHeader* 	respHeader;
	
	wpa_printf(MSG_INFO,"EAP-WSC: Entered eap_wsc_process");

	switch(pEapWsc->smState)
	{
		case EAP_WSC_STATE_START:
			
			if (OK != EapWsc_CheckMsg(pEapWsc->smState, reqData, reqDataLen, hdr, ret)) return NULL;				
			res = EapWsc_HandleMsg(pEapWsc, NULL, &OutMsg);
			if(res != OK)
        	{
				pEapWsc->smState = EAP_WSC_STATE_FAILURE;
				ret->ignore = TRUE;
				return NULL;
        	}
			/* set the message state to CONTINUE */
			pEapWsc->smState = EAP_WSC_STATE_CONTINUE;
			break;

		case EAP_WSC_STATE_CONTINUE:
			
			if (OK != EapWsc_CheckMsg(pEapWsc->smState, reqData, reqDataLen, hdr, ret)) return NULL;
			bufferCreateFill(&InMsg, (u8*)(reqData + WSC_EAP_PACKET_HEADER_LEN), reqDataLen - WSC_EAP_PACKET_HEADER_LEN);
			res = EapWsc_HandleMsg(pEapWsc, &InMsg, &OutMsg);
				if(res != OK)
				{
					pEapWsc->smState = EAP_WSC_STATE_FAILURE;
					ret->ignore = TRUE;
					return NULL;
				}
			break;

		case EAP_WSC_STATE_SUCCESS:
		case EAP_WSC_STATE_FAILURE:
			break;
	}

	/*
	handle success and failure states
	*/
	switch(pEapWsc->smState)
	{
		case EAP_WSC_STATE_START:
		case EAP_WSC_STATE_CONTINUE:
			break;
			
		case EAP_WSC_STATE_SUCCESS:

			ret->methodState = METHOD_DONE;
			break;
			
		case EAP_WSC_STATE_FAILURE:

			wpa_printf(MSG_ERROR,"EAP-WSC: eap_wsc_process: FAILURE");

			/* reset the SM */
			EapWsc_RestartSM(pEapWsc);
			ret->ignore = TRUE;
			return NULL;			
	}

	resp = (u8 *) malloc(bufferLength(&OutMsg) + WSC_EAP_PACKET_HEADER_LEN);
    if (!resp)
    {
		wpa_printf(MSG_ERROR,"EAP-WSC: eap_wsc_process: Memory allocation for response - failed");
		pEapWsc->smState = EAP_WSC_STATE_FAILURE;
		bufferFree(&OutMsg);
        ret->ignore = TRUE;
	    return NULL;
    }

	respHeader = (TEapWscPacketHeader*) resp;

	respHeader->code = WSC_EAP_CODE_RESPONSE;
	respHeader->id = hdr->id;
	respHeader->len = htons((u16)(bufferLength(&OutMsg) + WSC_EAP_PACKET_HEADER_LEN));
	respHeader->type = WSC_EAP_TYPE;
	respHeader->vendorId[0] = WSC_VENDORID_0;
	respHeader->vendorId[1] = WSC_VENDORID_1;
	respHeader->vendorId[2] = WSC_VENDORID_2;
	respHeader->vendorType = htonl(WSC_VENDORTYPE);

	if (pEapWsc->LastMessageSent == WSC_ID_MESSAGE_ACK)
	{
		respHeader->opCode = WSC_ACK;
	}
	else if (pEapWsc->LastMessageSent == WSC_ID_MESSAGE_DONE)
	{
		respHeader->opCode = WSC_Done;
	}
	else
	{
		respHeader->opCode = WSC_MSG;
	}

	respHeader->flags = 0;

    if (bufferGetBuf(&OutMsg) != NULL)
    {
        memcpy((resp + WSC_EAP_PACKET_HEADER_LEN), bufferGetBuf(&OutMsg), bufferLength(&OutMsg));
    }

    *respDataLen = bufferLength(&OutMsg) + WSC_EAP_PACKET_HEADER_LEN;
	bufferFree(&OutMsg);

    ret->ignore = FALSE;
    ret->decision = DECISION_COND_SUCC;
    ret->allowNotifications = FALSE;

    return resp;

}

int eap_peer_wsc_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_WSC, "WSC");
	if (eap == NULL)
		return -1;

	eap->init = eap_wsc_init;
	eap->deinit = eap_wsc_deinit;
	eap->process = eap_wsc_process;

	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret;
}

void EapWsc_EapFailureRecv(void *priv)
{
	TEapWsc* pEapWsc = priv;

#ifdef CONFIG_EAP_WSC
  if((pEapWsc->pWscSupplicantConfig->WscMode == WSC_MODE_PBC)||(pEapWsc->pWscSupplicantConfig->WscMode == WSC_MODE_PIN))
#endif
  {
    
	if (pEapWsc->smState == EAP_WSC_STATE_SUCCESS)
	{
		/* 
		this is the EAP-FAIL at the end of the WPS handshake 
		so now we need to do the real authentication 
		*/
		wsc_supplicant_EapSuccess(pEapWsc->pStaEncryptSettings);
	}

    EapWsc_RestartSM(pEapWsc); /* Reset the struct of eap_wsc EAP method state machine */
  }
}
