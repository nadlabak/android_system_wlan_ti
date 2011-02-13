/*
 * WscTypes.h
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

#ifndef _WSC_TYPES_H_
#define _WSC_TYPES_H_

/* defines */
/***********/

#define SIZE_1_BYTE         1
#define SIZE_2_BYTES        2
#define SIZE_4_BYTES        4
#define SIZE_6_BYTES        6
#define SIZE_8_BYTES        8
#define SIZE_16_BYTES       16
#define SIZE_20_BYTES       20
#define SIZE_32_BYTES       32
#define SIZE_64_BYTES       64
#define SIZE_80_BYTES       80
#define SIZE_128_BYTES      128
#define SIZE_192_BYTES      192


#define SIZE_64_BITS        8
#define SIZE_128_BITS       16
#define SIZE_160_BITS       20
#define SIZE_256_BITS       32
#define SIZE_512_BITS       64

#define SIZE_ENCR_IV            SIZE_128_BITS
#define ENCR_DATA_BLOCK_SIZE    SIZE_128_BITS
#define SIZE_DATA_HASH          SIZE_160_BITS
#define SIZE_PUB_KEY_HASH       SIZE_160_BITS
#define SIZE_UUID               SIZE_16_BYTES
#define SIZE_PUB_KEY            SIZE_192_BYTES /* 1536 BITS */

#define SIZE_VERSION            SIZE_1_BYTE
#define SIZE_MSG_TYPE           SIZE_1_BYTE
#define SIZE_ENROLLEE_NONCE     SIZE_128_BITS
#define SIZE_REGISTRAR_NONCE    SIZE_128_BITS
#define SIZE_PRIM_DEV_TYPE			SIZE_8_BYTES
#define SIZE_PRIM_DEV_CAT_ID		SIZE_2_BYTES
#define SIZE_PRIM_DEV_OUI			SIZE_4_BYTES
#define SIZE_PRIM_DEV_SUB_CAT_ID	SIZE_2_BYTES
#define SIZE_AUTH_TYPE_FLAGS    SIZE_2_BYTES
#define SIZE_ENCR_TYPE_FLAGS    SIZE_2_BYTES
#define SIZE_CONN_TYPE_FLAGS    SIZE_1_BYTE
#define SIZE_CONFIG_METHODS		SIZE_2_BYTES
#define SIZE_SC_STATE			SIZE_1_BYTE
#define SIZE_MANUFACTURER		SIZE_32_BYTES
#define SIZE_MODEL_NAME			SIZE_32_BYTES
#define SIZE_MODEL_NUMBER		SIZE_32_BYTES
#define SIZE_SERIAL_NUMBER		SIZE_32_BYTES
#define SIZE_DEVICE_NAME		SIZE_32_BYTES
#define SIZE_RF_BAND			SIZE_1_BYTE
#define SIZE_ASSOC_STATE		SIZE_2_BYTES
#define SIZE_DEVICE_PWD_ID		SIZE_2_BYTES
#define SIZE_CONFIG_ERROR		SIZE_2_BYTES
#define SIZE_OS_VERSION			SIZE_4_BYTES
#define SIZE_E_HASH			    SIZE_256_BITS
#define SIZE_AUTHENTICATOR		SIZE_64_BITS
#define SIZE_E_SNONCE			SIZE_128_BITS
#define SIZE_KEY_WRAP_AUTH		SIZE_64_BITS
#define SIZE_REQ_TYPE			SIZE_1_BYTE

#define MAX_ENROLLEE_NONCE		SIZE_128_BITS
#define MAX_REGISTRAR_NONCE		SIZE_128_BITS
#define MAX_UUID	            SIZE_128_BITS
#define MAX_PUB_KEY	            SIZE_192_BYTES /* 1536 BITS */
#define MAX_AUTHENTICATOR       SIZE_256_BITS
#define MAX_SSID	            SIZE_32_BYTES
#define MAX_MAC_ADDR            SIZE_6_BYTES
#define MAX_KEY_WRAP_AUTH       SIZE_64_BITS
#define MAX_R_HASH	            SIZE_256_BITS
#define MAX_R_SNONCE	        SIZE_128_BITS
#define MAX_NW_KEY	            SIZE_512_BITS
#define MAX_NEW_PWD	            SIZE_64_BYTES

#define PRF_DIGEST_SIZE         BUF_SIZE_256_BITS
#define KDF_KEY_BITS            640

#define BUF_SIZE_64_BITS    8
#define BUF_SIZE_128_BITS   16
#define BUF_SIZE_160_BITS   20
#define BUF_SIZE_256_BITS   32
#define BUF_SIZE_512_BITS   64
#define BUF_SIZE_1024_BITS  128
#define BUF_SIZE_1536_BITS  192

#define RANDOM_PIN_NUMBER "********"
#define RANDOM_SHORT_PIN_NUMBER "****"

/* Data Element Definitions */
#define WSC_ID_AP_CHANNEL         0x1001
#define WSC_ID_ASSOC_STATE        0x1002
#define WSC_ID_AUTH_TYPE          0x1003
#define WSC_ID_AUTH_TYPE_FLAGS    0x1004
#define WSC_ID_AUTHENTICATOR      0x1005
#define WSC_ID_CONFIG_METHODS     0x1008
#define WSC_ID_CONFIG_ERROR       0x1009
#define WSC_ID_CONF_URL4          0x100A
#define WSC_ID_CONF_URL6          0x100B
#define WSC_ID_CONN_TYPE          0x100C
#define WSC_ID_CONN_TYPE_FLAGS    0x100D
#define WSC_ID_CREDENTIAL         0x100E
#define WSC_ID_DEVICE_NAME        0x1011
#define WSC_ID_DEVICE_PWD_ID      0x1012
#define WSC_ID_E_HASH1            0x1014
#define WSC_ID_E_HASH2            0x1015
#define WSC_ID_E_SNONCE1          0x1016
#define WSC_ID_E_SNONCE2          0x1017
#define WSC_ID_ENCR_SETTINGS      0x1018
#define WSC_ID_ENCR_TYPE          0x100F
#define WSC_ID_ENCR_TYPE_FLAGS    0x1010
#define WSC_ID_ENROLLEE_NONCE     0x101A
#define WSC_ID_FEATURE_ID         0x101B
#define WSC_ID_IDENTITY           0x101C
#define WSC_ID_IDENTITY_PROOF     0x101D
#define WSC_ID_INIT_VECTOR        0x1060
#define WSC_ID_KEY_WRAP_AUTH      0x101E
#define WSC_ID_KEY_IDENTIFIER     0x101F
#define WSC_ID_MAC_ADDR           0x1020
#define WSC_ID_MANUFACTURER       0x1021
#define WSC_ID_MSG_TYPE           0x1022
#define WSC_ID_MODEL_NAME         0x1023
#define WSC_ID_MODEL_NUMBER       0x1024
#define WSC_ID_NW_INDEX           0x1026
#define WSC_ID_NW_KEY             0x1027
#define WSC_ID_NW_KEY_INDEX       0x1028
#define WSC_ID_NEW_DEVICE_NAME    0x1029
#define WSC_ID_NEW_PWD            0x102A        
#define WSC_ID_OOB_DEV_PWD        0x102C
#define WSC_ID_OS_VERSION         0x102D
#define WSC_ID_POWER_LEVEL        0x102F
#define WSC_ID_PSK_CURRENT        0x1030
#define WSC_ID_PSK_MAX            0x1031
#define WSC_ID_PUBLIC_KEY         0x1032
#define WSC_ID_RADIO_ENABLED      0x1033
#define WSC_ID_REBOOT             0x1034
#define WSC_ID_REGISTRAR_CURRENT  0x1035
#define WSC_ID_REGISTRAR_ESTBLSHD 0x1036
#define WSC_ID_REGISTRAR_LIST     0x1037
#define WSC_ID_REGISTRAR_MAX      0x1038
#define WSC_ID_REGISTRAR_NONCE    0x1039
#define WSC_ID_REQ_TYPE           0x103A
#define WSC_ID_RESP_TYPE          0x103B
#define WSC_ID_RF_BAND            0x103C
#define WSC_ID_R_HASH1            0x103D
#define WSC_ID_R_HASH2            0x103E
#define WSC_ID_R_SNONCE1          0x103F
#define WSC_ID_R_SNONCE2          0x1040
#define WSC_ID_SEL_REGISTRAR      0x1041
#define WSC_ID_SERIAL_NUM         0x1042
#define WSC_ID_SC_STATE           0x1044
#define WSC_ID_SSID               0x1045
#define WSC_ID_TOT_NETWORKS       0x1046
#define WSC_ID_UUID_E             0x1047
#define WSC_ID_UUID_R             0x1048
#define WSC_ID_VENDOR_EXT         0x1049
#define WSC_ID_VERSION            0x104A
#define WSC_ID_X509_CERT_REQ      0x104B
#define WSC_ID_X509_CERT          0x104C
#define WSC_ID_EAP_IDENTITY       0x104D
#define WSC_ID_MSG_COUNTER        0x104E
#define WSC_ID_PUBKEY_HASH        0x104F
#define WSC_ID_REKEY_KEY          0x1050
#define WSC_ID_KEY_LIFETIME       0x1051
#define WSC_ID_PERM_CFG_METHODS   0x1052
#define WSC_ID_SEL_REG_CFG_METHODS 0x0153
#define WSC_ID_PRIM_DEV_TYPE      0x1054
#define WSC_ID_SEC_DEV_TYPE_LIST  0x1055
#define WSC_ID_PORTABLE_DEVICE    0x1056
#define WSC_ID_AP_SETUP_LOCKED    0x1057
#define WSC_ID_APP_LIST           0x1058

#define WSC_ID_EAP_TYPE           0x1059
#define WSC_ID_INIT_VECTOR        0x1060
#define WSC_ID_KEY_PROVIDED_AUTO  0x1061
#define WSC_ID_802_1_X_ENABLED    0x1062  
#define WSC_ID_APP_SESSION_KEY    0x1063
#define WSC_ID_WEP_TRANSMIT_KEY   0x1064

/* Authentication types */
#define WSC_AUTHTYPE_OPEN        0x0001
#define WSC_AUTHTYPE_WPAPSK      0x0002
#define WSC_AUTHTYPE_SHARED      0x0004
#define WSC_AUTHTYPE_WPA         0x0008
#define WSC_AUTHTYPE_WPA2        0x0010
#define WSC_AUTHTYPE_WPA2PSK     0x0020

/* Encryption types */
#define WSC_ENCRTYPE_NONE        0x0001
#define WSC_ENCRTYPE_WEP         0x0002
#define WSC_ENCRTYPE_TKIP        0x0004
#define WSC_ENCRTYPE_AES         0x0008

/* Config methods */
#define WSC_CONFMET_USBA            	0x0001
#define WSC_CONFMET_ETHERNET        	0x0002
#define WSC_CONFMET_LABEL           	0x0004
#define WSC_CONFMET_DISPLAY         	0x0008
#define WSC_CONFMET_EXT_NFC_TOK     	0x0010
#define WSC_CONFMET_INT_NFC_TOK     	0x0020
#define WSC_CONFMET_NFC_INTF        	0x0040
#define WSC_CONFMET_PBC             	0x0080
#define WSC_CONFMET_KEYPAD          	0x0100

/* Device password ID */
#define WSC_DEVICEPWDID_DEFAULT      0x0000
#define WSC_DEVICEPWDID_USER_SPEC    0x0001
#define WSC_DEVICEPWDID_MACHINE_SPEC 0x0002
#define WSC_DEVICEPWDID_REKEY			0x0003
#define WSC_DEVICEPWDID_PUSH_BTN     0x0004
#define WSC_DEVICEPWDID_REG_SPEC     0x0005






/* types */
/*********/


/* functions */
/*************/

#endif  /* _WSC_TYPES_H_ */
        
