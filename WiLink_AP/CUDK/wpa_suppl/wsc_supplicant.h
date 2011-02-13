/*
 * wsc_supplicant.h
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

#ifndef WSC_SUPPLICANT_H
#define WSC_SUPPLICANT_H

#include "bufferObj.h"

#define WSC_STATE_IDLE		0
#define WSC_STATE_ASSOC		1
#define WSC_STATE_EVENT_ASSOC	2
#define WSC_STATE_SUCCESS		3

#define MAX_MANUFACTURER		64
#define MAX_MODEL_NAME			32
#define MAX_MODEL_NUMBER		32
#define MAX_SERIAL_NUMBER		32
#define MAX_DEVICE_NAME		32
#define MAX_PASSWORD_SIZE		64 /* Password is actually the PIN */
#define MAX_NETWORK_KEY_NUM  	4
#define DEFAULT_KEY_INDEX    	1

#define LONG_PIN_LEN			8
#define SHORT_PIN_LEN			4

typedef struct
{
	int length;
	u8* pValue;
} TLVPUINT8;

typedef struct
{
	int length;
	char* pValue;
} TLVPCHAR;

typedef struct
{
    /* Required attributes */
    u8         			nwIndex;
    TLVPUINT8			ssid;
    u16        			authType;
    u16        			encrType;
    u8      			nwKeyIndex;
    u8      			wepTransmitKey;    
    TLVPCHAR           	nwKey[MAX_NETWORK_KEY_NUM];    
    TLVPUINT8         	macAddr;

    /* Optional attributes */
    TLVPUINT8  			eapType; /* TBD: Define this */
    u8         			bKey_Provided_Automatically;
    u8         			b_Is_802_1x_enabled;
    u8         			WEP_transmit_key;

    TLVPUINT8           eapIdentity; /* TBD: Define this */
    u32     			keyLifetime; /* TBD: Define this */
    void*       		vendorExt;  /* TBD: Ignore for now */
    TLVPUINT8        	rekeyKey;
    TLVPUINT8        	x509Cert;
}TTlvCredential;


typedef struct
{
    TTlvCredential     	credential; /* this is the first credential that is delivered inside M8. In the future this can be replaced with a list of credentials */
    TLVPCHAR          	new_pwd;
    u16     			pwdId;
    TLVPUINT8   		keyWrapAuth; /* reuse Authenticator data struct */
} TStaEncryptSettings;


typedef struct
{
	u16 category_id;
	u16 sub_category_id;
	u32 oui; /* =0x0050F204 */	
} TWscSupplicant_DeviceType;

typedef struct
{
	u8 		macAddress[ETH_ALEN];
	u8 		version; /* (0x104A) */	
	u16 	configMethods; /* (0x1008) */
	u8 		uuidE[32]; /* (0x1047) */
	TWscSupplicant_DeviceType primaryDeviceType; /* (0x1054) */
	u8 		rfBand; /* (0x103C) */
	u16		devicePasswordId; /* (0x1012) */
	u16 	authenticationTypeFlags; /* (0x1004) */
	u16 	encryptionTypeFlags; /* (0x1010) */
	u8 		connectionTypeFlags; /* (0x100D) */
	u8 		state; /* (0x1044) */
	char 	manufacturer[MAX_MANUFACTURER]; /* (0x1021) */
	char 	modelName[MAX_MODEL_NAME]; /* (0x1023) */
	char 	modelNumber[MAX_MODEL_NUMBER]; /* (0x1024) */
	char 	serialNumber[MAX_SERIAL_NUMBER]; /* (0x1042) */
	char 	deviceName[MAX_DEVICE_NAME]; /* (0x1011) */
	u16 	assocState; /* (0x1002) */
	u16 	configError; /* (0x1009) */
	u32 	osVersion; /* (0x102D) */
	u8 		password[MAX_PASSWORD_SIZE]; /* This is the PIN number of the AP, although in some technologies it is changable */

	void*	ssid;
	void*	wpa_s;		
	u32 	smState;
	u32 	WscMode;
} TWscSupplicant;

void wsc_supplicant_associate(void* h_wpa_s, void* h_ssid, u32 WscMode);
void wsc_supplicant_EapSuccess(TStaEncryptSettings* pStaEncryptSettings);
void wsc_supplicant_event_assoc(void* h_ssid);
void wsc_supplicant_event_overlap();
int wsc_supplicant_associate_timeout_calc(void);
void wsc_supplicant_stop();
u32 wsc_supplicant_SerializeHeader(u16 type, u16 len, bufferObj *outBuf);
u32 wsc_supplicant_SerializeField(u16 type, bufferObj *outBuf, u16 len, u8 *data);
TWscSupplicant* wsc_supplicant_GetWscSupplicantConfig(void);
u32 wsc_supplicant_ComputeChecksum(u32 PIN );

#endif /* WSC_SUPPLICANT_H */
