/*
 * wsc_supplicant.c
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
#include "config_ssid.h"
#include "wpa_supplicant.h"
#include "wpa_supplicant_i.h"
#include "eloop.h"
#include "wpa.h"
#include "config.h"
#include "WscTypes.h"
#include "wsc_supplicant.h"

#include "ossl_typ.h"
#include "rand.h"


#define DEF_CONFIG_VERSION					0x10
#define DEF_CONFIG_CONFIG_METHODS			0xc
#define DEF_CONFIG_UUID						"0x01010101010101010101010101010101"
#define DEF_CONFIG_PRIMARY_DEV_CATEGORY		1
#define DEF_CONFIG_PRIMARY_DEV_OUI			0x50f204
#define DEF_CONFIG_PRIMARY_DEV_SUB_CATEGORY	1
#define DEF_CONFIG_RF_BAND					1
#define DEF_CONFIG_AUTH_TYPE_FLAGS			0x3f
#define DEF_CONFIG_ENCR_TYPE_FLAGS			0x6
#define DEF_CONFIG_CONN_TYPE_FLAGS			0x3
#define DEF_CONFIG_MANUFACTURER				"Texas Instruments"
#define DEF_CONFIG_MODEL_NAME					"Texas Instruments 1251"
#define DEF_CONFIG_MODEL_NUMBER				"1251"
#define DEF_CONFIG_SERIAL_NUMBER				"0"
#define DEF_CONFIG_DEVICE_NAME				"TI Device"
#define DEF_CONFIG_OS_VERSION					0x80000000

#define ENROLLEE_ID_STRING        			"WFA-SimpleConfig-Enrollee-1-0"

TWscSupplicant WscSupplicantConfig;

static u32 wsc_supplicant_BuildProbeRequest(TWscSupplicant* pWscSupplicant, bufferObj *probeReqBuf)
{
	u8 RequestType = 0; /* 0 - Enrollee, Info only, 1 - Enrollee, open 802.1X */
	u16 AssociationState = 0; /* 0 - Not Associated */
	u16 ConfigurationError = 0; /* 0 - No Error */

	/* u8 version */
	wsc_supplicant_SerializeField(WSC_ID_VERSION, probeReqBuf, SIZE_VERSION, &(pWscSupplicant->version));

	/* u8 RequestType */
	wsc_supplicant_SerializeField(WSC_ID_REQ_TYPE, probeReqBuf, SIZE_REQ_TYPE, &RequestType);

	/* u16 configMethods */
	wsc_supplicant_SerializeField(WSC_ID_CONFIG_METHODS, probeReqBuf, SIZE_CONFIG_METHODS, (u8 *)&(pWscSupplicant->configMethods));

	/* u8 *uuid ;16B=128 bits */
	wsc_supplicant_SerializeField(WSC_ID_UUID_E, probeReqBuf, SIZE_UUID, pWscSupplicant->uuidE);

	/* sc_device_type_t primaryDeviceType; 8B */
	wsc_supplicant_SerializeHeader(WSC_ID_PRIM_DEV_TYPE, SIZE_PRIM_DEV_TYPE, probeReqBuf);
	bufferAppend(probeReqBuf, SIZE_PRIM_DEV_CAT_ID, (u8 *)&(pWscSupplicant->primaryDeviceType.category_id));
	bufferAppend(probeReqBuf, SIZE_PRIM_DEV_OUI, (u8 *)&(pWscSupplicant->primaryDeviceType.oui));
	bufferAppend(probeReqBuf, SIZE_PRIM_DEV_SUB_CAT_ID, (u8 *)&(pWscSupplicant->primaryDeviceType.sub_category_id));

	/* u8 rfBand */
	wsc_supplicant_SerializeField(WSC_ID_RF_BAND, probeReqBuf, SIZE_RF_BAND, &(pWscSupplicant->rfBand));

	/* u16 assocState */
	wsc_supplicant_SerializeField(WSC_ID_ASSOC_STATE, probeReqBuf, SIZE_ASSOC_STATE, (u8 *)&AssociationState);

	/* u16 configError */
	wsc_supplicant_SerializeField(WSC_ID_CONFIG_ERROR, probeReqBuf, SIZE_CONFIG_ERROR, (u8 *)&ConfigurationError);

	/* u16 devicePasswordId */
	wsc_supplicant_SerializeField(WSC_ID_DEVICE_PWD_ID, probeReqBuf, SIZE_DEVICE_PWD_ID, (u8 *)&(pWscSupplicant->devicePasswordId));

	wpa_printf(MSG_INFO,"wsc_supplicant: wsc_supplicant_BuildProbeRequest: built %d byte message", bufferLength(probeReqBuf));

	return OK;
}

static void wsc_supplicant_PushButtonWalktimeTimeout(void *eloop_ctx, void *timeout_ctx)
{
	
	wpa_printf(MSG_INFO,"wsc_supplicant: wsc_supplicant_PushButtonWalktimeTimeout: 2 Min.Push-Button walk-time timed out.");

	wpa_supplicant_disassociate(WscSupplicantConfig.wpa_s, REASON_DEAUTH_LEAVING);
    wpa_drv_disassociate((struct wpa_supplicant *)WscSupplicantConfig.wpa_s, ((struct wpa_supplicant*)WscSupplicantConfig.wpa_s)->bssid, REASON_DEAUTH_LEAVING);

}			

 /* configure supplicant & update driver according to new mode of operation */
void wsc_supplicant_associate(void* h_wpa_s, void* h_ssid, u32 WscMode)
{
	int i;		
	bufferObj probeReqBuf;
	struct wpa_supplicant *wpa_s = h_wpa_s;
	struct wpa_ssid *ssid = h_ssid;

	/* 
	if the current state is WSC_STATE_SUCCESS this means that this is the second association 
	in the WPS sequence and we are not supposed to start the EAP-WSC mechnaism.
	*/
	if(WscSupplicantConfig.smState == WSC_STATE_SUCCESS)
	{
		WscSupplicantConfig.smState = WSC_STATE_IDLE;
		return;
	}

	/* 
	if the current state is WSC_STATE_IDLE this means that this is a interruption of 
	the current WPS session.
	*/
	if(WscSupplicantConfig.smState != WSC_STATE_IDLE)
	{
		if(WscSupplicantConfig.WscMode == WSC_MODE_PBC)
		{
			/* 
			If Supplicant is in a process of a Simple Config handhsake and in PBC mode - 
			Cancel registration to 2 Min. Walk-Time PushButton timeout
			*/		
			eloop_cancel_timeout(wsc_supplicant_PushButtonWalktimeTimeout, NULL, NULL);
		}

        /* update driver */
		wpa_drv_set_wsc_mode(h_wpa_s,
					  		WSC_MODE_OFF,
					  		NULL, 
					  		0);
	}

	wpa_printf(MSG_INFO,"wsc_supplicant: Entered wsc_supplicant_associate");
	
	/* init params */
	WscSupplicantConfig.version = DEF_CONFIG_VERSION;
	WscSupplicantConfig.configMethods = DEF_CONFIG_CONFIG_METHODS;
	{
		char temp[10];
		char *p = DEF_CONFIG_UUID;
    	temp[0] = '0';
    	temp[1] = 'x';
        
		/* move past the '0x' on the first pass */
		for (i = 0; i <= 15; i++)
		{
    		p += 2;
        	strncpy(&temp[2], p, 2); 
        	WscSupplicantConfig.uuidE[i] = (u8) (strtoul(temp, NULL, 16));    
		}
	}
	WscSupplicantConfig.primaryDeviceType.category_id = DEF_CONFIG_PRIMARY_DEV_CATEGORY;
	WscSupplicantConfig.primaryDeviceType.oui = DEF_CONFIG_PRIMARY_DEV_OUI;
	WscSupplicantConfig.primaryDeviceType.sub_category_id = DEF_CONFIG_PRIMARY_DEV_SUB_CATEGORY;
	WscSupplicantConfig.rfBand = DEF_CONFIG_RF_BAND;
	WscSupplicantConfig.devicePasswordId = WSC_DEVICEPWDID_DEFAULT; /* Default (PIN) */

	WscSupplicantConfig.authenticationTypeFlags = DEF_CONFIG_AUTH_TYPE_FLAGS;
	memcpy(WscSupplicantConfig.macAddress, wpa_s->own_addr, ETH_ALEN);
	WscSupplicantConfig.encryptionTypeFlags = DEF_CONFIG_ENCR_TYPE_FLAGS;
	WscSupplicantConfig.connectionTypeFlags = DEF_CONFIG_CONN_TYPE_FLAGS;
	WscSupplicantConfig.state = 0;
	WscSupplicantConfig.assocState = 0;
	WscSupplicantConfig.configError = 0;
	sprintf(WscSupplicantConfig.manufacturer, "%s", DEF_CONFIG_MANUFACTURER);
	sprintf(WscSupplicantConfig.modelName, "%s", DEF_CONFIG_MODEL_NAME);
	sprintf(WscSupplicantConfig.modelNumber, "%s", DEF_CONFIG_MODEL_NUMBER);
	sprintf(WscSupplicantConfig.serialNumber, "%s", DEF_CONFIG_SERIAL_NUMBER);
	sprintf(WscSupplicantConfig.deviceName, "%s", DEF_CONFIG_DEVICE_NAME);
	WscSupplicantConfig.osVersion = DEF_CONFIG_OS_VERSION;
	
	WscSupplicantConfig.ssid = ssid;
	WscSupplicantConfig.wpa_s = wpa_s;
	

	switch (WscMode)
	{
		case WSC_MODE_PIN:
			if(!ssid->wsc_pin)
			{
				char c_devPwd[32];
				u8 devPwd[10];
				u32 val;
				u32 checksum;
				
				RAND_bytes(devPwd, LONG_PIN_LEN); 
				sprintf(c_devPwd, "%08u", *(u32 *)devPwd);
				
				/* Compute the checksum */
				c_devPwd[7] = '\0';
				val = strtoul(c_devPwd, NULL, 10 );
				checksum = wsc_supplicant_ComputeChecksum( val );
				val = val*10 + checksum;
				sprintf((char *)(WscSupplicantConfig.password), "%d", val );
				WscSupplicantConfig.password[LONG_PIN_LEN] = '\0';		
				wpa_printf(MSG_INFO, "Random PIN: %c-%c-%c-%c-%c-%c-%c-%c\n", 
					WscSupplicantConfig.password[0], 
					WscSupplicantConfig.password[1], 
					WscSupplicantConfig.password[2], 
					WscSupplicantConfig.password[3], 
					WscSupplicantConfig.password[4], 
					WscSupplicantConfig.password[5], 
					WscSupplicantConfig.password[6], 
					WscSupplicantConfig.password[7]);
			}
			else
			{
				strcpy((char *)(WscSupplicantConfig.password), ssid->wsc_pin);
				ssid->wsc_pin[strlen(ssid->wsc_pin)] = '\0';
			}	
			break;

		case WSC_MODE_PBC:

			for (i = 0 ; i < LONG_PIN_LEN; i++)
			{
				WscSupplicantConfig.password[i] = '0';
			}
			WscSupplicantConfig.password[LONG_PIN_LEN] = '\0';

			WscSupplicantConfig.configMethods |= WSC_CONFMET_PBC;
			WscSupplicantConfig.devicePasswordId = WSC_DEVICEPWDID_PUSH_BTN;
				
			/* Register for 2 Min. Walk-Time PushButton timeout */
            eloop_register_timeout(120, 0, wsc_supplicant_PushButtonWalktimeTimeout, NULL, NULL);
            
			break;

		default:
			
			wpa_printf(MSG_ERROR,"wsc_supplicant: wsc_supplicant_associate: ERROR: Incompatible Simple Config Mode received in scStartEnrollee: (%d)", WscMode);
			WscSupplicantConfig.smState = WSC_STATE_IDLE;
	}
			
	bufferCreateChunk(&probeReqBuf);
	wsc_supplicant_BuildProbeRequest(&WscSupplicantConfig, &probeReqBuf);

	wpa_drv_set_wsc_mode(h_wpa_s,
			  				WscMode,
			  				bufferGetBuf(&probeReqBuf), 
			  				bufferLength(&probeReqBuf));

	bufferFree(&probeReqBuf);

	ssid->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	ssid->auth_alg = WPA_AUTH_ALG_OPEN;
	ssid->proto = WPA_PROTO_WPA;
	ssid->pairwise_cipher = WPA_CIPHER_TKIP;
	ssid->group_cipher = WPA_CIPHER_TKIP;
	ssid->identity = (u8 *) strdup(ENROLLEE_ID_STRING);
	ssid->identity_len = strlen(ENROLLEE_ID_STRING);								

	WscSupplicantConfig.WscMode = WscMode;	
	WscSupplicantConfig.smState = WSC_STATE_ASSOC;
}

void wsc_supplicant_EapSuccess(TStaEncryptSettings* pStaEncryptSettings)
{
	struct wpa_ssid *ssid = WscSupplicantConfig.ssid;
	int i;		
	/* for now we only support one credential inside M8 settings */
	TTlvCredential *p_Credentials = &(pStaEncryptSettings->credential);

	WscSupplicantConfig.smState = WSC_STATE_SUCCESS;

    wpa_drv_set_wsc_mode(WscSupplicantConfig.wpa_s,
	    			  	 WSC_MODE_OFF,
					  	 NULL, 
					  	 0);

	wpa_printf (MSG_DEBUG, "wsc_supplicant: wsc_supplicant_EapSuccess: Acquired network block authType = 0x%x",p_Credentials->authType);

	if ((p_Credentials->authType & WSC_AUTHTYPE_WPAPSK) || (p_Credentials->authType & WSC_AUTHTYPE_WPA2PSK) || (p_Credentials->authType & WSC_AUTHTYPE_OPEN) || (p_Credentials->authType & WSC_AUTHTYPE_SHARED))
	{

		ssid->mode = IEEE80211_MODE_INFRA;
        ssid->proto = DEFAULT_PROTO;
        ssid->key_mgmt = WPA_KEY_MGMT_NONE;
        ssid->auth_alg = AUTH_ALG_OPEN_SYSTEM;
        
		if ((p_Credentials->authType & WSC_AUTHTYPE_WPAPSK) || (p_Credentials->authType & WSC_AUTHTYPE_WPA2PSK))
		{
			wpa_printf (MSG_DEBUG, "wsc_supplicant: wsc_supplicant_EapSuccess: length of nw_key = %d",p_Credentials->nwKey[DEFAULT_KEY_INDEX].length);
			
			if (p_Credentials->nwKey[DEFAULT_KEY_INDEX].length == 64)
			{
				if( 0 == hexstr2bin ((char *)(p_Credentials->nwKey[DEFAULT_KEY_INDEX].pValue), (u8 *)(&ssid->psk), (p_Credentials->nwKey[DEFAULT_KEY_INDEX].length / 2)))
				{
					wpa_printf (MSG_DEBUG, "wsc_supplicant: wsc_supplicant_EapSuccess: successfully converted hex string into binary data");
					ssid->psk_set=1;
				}
				else
				{
					wpa_printf (MSG_ERROR, "wsc_supplicant: wsc_supplicant_EapSuccess: sorry but I couldn't convert hex string into binary data");
				}
			}
			else if ((p_Credentials->nwKey[DEFAULT_KEY_INDEX].length < 64) && (p_Credentials->nwKey[DEFAULT_KEY_INDEX].length > 0))
			{
				/* put PSK */
				if(ssid->passphrase)
					free(ssid->passphrase);
				ssid->passphrase = malloc(p_Credentials->nwKey[DEFAULT_KEY_INDEX].length+1);
				strncpy(ssid->passphrase, p_Credentials->nwKey[DEFAULT_KEY_INDEX].pValue, p_Credentials->nwKey[DEFAULT_KEY_INDEX].length);
				ssid->passphrase[p_Credentials->nwKey[DEFAULT_KEY_INDEX].length] = '\0';
				ssid->psk_set=0;
				wpa_config_update_psk(ssid);
				wpa_printf (MSG_DEBUG,"wsc_supplicant: wsc_supplicant_EapSuccess: psk string (ASCII): %s",ssid->passphrase);
			}
		}
        else if (p_Credentials->authType & WSC_AUTHTYPE_SHARED)
        {
            ssid->auth_alg = WPA_AUTH_ALG_SHARED;
        }
        /* In case of WEP shared or open - get WEP key and TX key index*/
        if (p_Credentials->encrType & WSC_ENCRTYPE_WEP)
        {
            ssid->pairwise_cipher = WPA_CIPHER_NONE;
            ssid->group_cipher = WPA_CIPHER_NONE;
            ssid->wep_tx_keyidx = p_Credentials->WEP_transmit_key;

            for (i=0; i<MAX_NETWORK_KEY_NUM; i++)
            {
               /* In case of ASCII encoded keys */
               if ((p_Credentials->nwKey[DEFAULT_KEY_INDEX].length == 5) || (p_Credentials->nwKey[DEFAULT_KEY_INDEX].length == 13))
               {
                  /* ssid->wep_key */
               }
               /* In case of HEX encoded keys */
               else if ((p_Credentials->nwKey[DEFAULT_KEY_INDEX].length == 10) || (p_Credentials->nwKey[DEFAULT_KEY_INDEX].length == 26))
               {
                  /* ssid->wep_key */
               }
               else
               {
                  wpa_printf (MSG_ERROR,"wsc_supplicant: wrong WEP key length");
               }
            }
            
        }

		if (p_Credentials->authType & WSC_AUTHTYPE_WPAPSK)
		{
			ssid->key_mgmt = WPA_KEY_MGMT_PSK;
			ssid->proto = WPA_PROTO_WPA;
			ssid->pairwise_cipher = WPA_CIPHER_TKIP;
			ssid->group_cipher = WPA_CIPHER_TKIP;	
		}
		else if (p_Credentials->authType & WSC_AUTHTYPE_WPA2PSK)
		{
			ssid->key_mgmt = WPA_KEY_MGMT_PSK;
			ssid->proto = WPA_PROTO_RSN;
			ssid->pairwise_cipher = WPA_CIPHER_CCMP;
            // TI - we have no way to know that we are woking with MIX MODE , so this is the reason we configuere the group to CCMP|TKIP
            ssid->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
       	}
		else if (p_Credentials->authType & WSC_AUTHTYPE_OPEN)
		{
			ssid->key_mgmt = WPA_KEY_MGMT_NONE;
        }		
		
		wpa_config_write(((struct wpa_supplicant*)WscSupplicantConfig.wpa_s)->confname, ((struct wpa_supplicant*)WscSupplicantConfig.wpa_s)->conf);
	}
	else
	{
		wpa_printf (MSG_ERROR, "wsc_supplicant: wsc_supplicant_EapSuccess: Invalid Authentication algotirhm...aborting...");
		return;
	}


	ssid->disabled = 0;
    ssid->wsc_mode = WSC_MODE_OFF;
	((struct wpa_supplicant*)WscSupplicantConfig.wpa_s)->reassociate = 1;
	wpa_supplicant_req_scan(WscSupplicantConfig.wpa_s, 0, 0);
	
}


void wsc_supplicant_event_assoc(void* h_ssid)
{
	if(WscSupplicantConfig.smState == WSC_STATE_ASSOC)
	{		
		WscSupplicantConfig.smState  = WSC_STATE_EVENT_ASSOC;
		if(WscSupplicantConfig.WscMode == WSC_MODE_PBC)
		{
			eloop_cancel_timeout(wsc_supplicant_PushButtonWalktimeTimeout, NULL, NULL);
		}
	}
	
}

void wsc_supplicant_event_overlap()
{
	wpa_printf(MSG_INFO,"wsc_supplicant: wsc_supplicant_event_overlap: PBC overlapped event occured\n");

	wpa_supplicant_disassociate(WscSupplicantConfig.wpa_s, REASON_DEAUTH_LEAVING);
	
}

int wsc_supplicant_associate_timeout_calc(void)
{
	if((WscSupplicantConfig.smState == WSC_STATE_ASSOC) && (WscSupplicantConfig.WscMode == WSC_MODE_PBC))
		return 120; /* another 2 min of timeout */
	else
		return 0;
}

void wsc_supplicant_stop()
{
	wpa_printf(MSG_INFO,"wsc_supplicant: wsc_supplicant_stop: entered function\n");
	
	if(WscSupplicantConfig.smState == WSC_STATE_IDLE)
	{
		return;
	}

   
	wpa_drv_set_wsc_mode(WscSupplicantConfig.wpa_s,
					  		WSC_MODE_OFF,
					  		NULL, 
					  		0);
	
	if(WscSupplicantConfig.smState == WSC_STATE_ASSOC)
	{
		if(WscSupplicantConfig.WscMode == WSC_MODE_PBC)
		{
			/* 
			If Supplicant is in a process of a Simple Config handhsake and in PBC mode - 
			Cancel registration to 2 Min. Walk-Time PushButton timeout
			*/		
			eloop_cancel_timeout(wsc_supplicant_PushButtonWalktimeTimeout, NULL, NULL);
		}
	}

	WscSupplicantConfig.smState = WSC_STATE_IDLE;
	
}

u32 wsc_supplicant_SerializeHeader(u16 type, u16 len, bufferObj *outBuf)
{
	/* serializes the type and length.*/
	u8 temp[sizeof(u32)];

	/* Copy the Type */
	/*convert a u_short from host to TCP/IP network byte order (which is big-endian).*/
	*(u16 *)temp = htons(type);
	bufferAppend(outBuf, sizeof(u16), temp);

	/* Copy the Length */
	/* convert a u_short from host to TCP/IP network byte order (which is big-endian).*/
	*(u16 *)temp = htons(len);
	bufferAppend(outBuf, sizeof(u16), temp);

	return OK;
}

u32 wsc_supplicant_SerializeField(u16 type, bufferObj *outBuf, u16 len, u8 *data)
{
	u8 *pos;

	if((NULL == data) || (0 == len))
	{
		wpa_printf(MSG_ERROR,"wsc_supplicant: wsc_supplicant_SerializeField: serialize error - invalid empty parameter");
		return NOK;
	}
    
	/* Copy the Type & Length */
	wsc_supplicant_SerializeHeader(type, len, outBuf);

	/* Copy the Value */
	pos = bufferAppend(outBuf, len, data);

	/* The data has already been stored.*/
	/* Now convert it to network byte order as appropriate */
	if(len == sizeof(u32))
	{
		u32 Temp32;

		memcpy(&Temp32, pos, 4);
		Temp32 = htonl(Temp32);
		memcpy(pos, &Temp32, 4);
	}
	else if(len == sizeof(u16))
	{
		u16 Temp16;
		memcpy(&Temp16, pos, 2);
		Temp16 = htons(Temp16);
		memcpy(pos, &Temp16, 2);
	}	

	return OK;
}

TWscSupplicant* wsc_supplicant_GetWscSupplicantConfig(void)
{
	return &WscSupplicantConfig;
}

u32 wsc_supplicant_ComputeChecksum(u32 PIN )
{
    u32 accum = 0;
	int digit;

	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10); 
	accum += 1 * ((PIN / 1000000) % 10); 
	accum += 3 * ((PIN / 100000) % 10); 
	accum += 1 * ((PIN / 10000) % 10); 
	accum += 3 * ((PIN / 1000) % 10); 
	accum += 1 * ((PIN / 100) % 10); 
	accum += 3 * ((PIN / 10) % 10); 

	digit = (accum % 10);
	return (10 - digit) % 10;
}



