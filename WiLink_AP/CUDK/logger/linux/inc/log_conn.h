/*
 * log_conn.h
 *
 * Copyright 2001-2010 Texas Instruments, Inc. - http://www.ti.com/
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and  
 * limitations under the License.
 */
#ifndef _LOG_CONN_H
#define _LOG_CONN_H

#include "cu_osapi.h"

#define LOGGER_DEFAULT_PORT		        700
#define RPC_BUFFER_SIZE                 2000
#define MSG_PREFIX                      0x34
#define DEVICE_NAME                     "tiwlan0"
#define MESSAGE_HEADER_SIZE             6

#define IS_MESSAGE_AFTER_CONNECT(X)         (X[0] == 0x00 && \
                                             X[1] == 0x35 && \
                                             X[2] == 0x31 && \
                                             X[3] == 0xff)

typedef struct {
	THandle listen_sock;
	THandle data_sock;
	U32	connections;
} LOG_CONN_DATA, *PLOG_CONN_DATA;

typedef struct {
	U16 port_num;
} TLoggerConnParams, *PTLoggerConnParams;

typedef enum {
	LOG_CONN_MEDIA_SERIAL,
	LOG_CONN_MEDIA_ETH
} ELoggerConnMedia;

THandle loggerConn_Create(VOID);

TI_BOOL loggerConn_init (THandle loggerConn, 
					 ELoggerConnMedia mediaType,		/*currently unused */
					 TLoggerConnParams* mediaParams
					 );

TI_BOOL loggerConn_waitForConn (THandle loggerConn);
TI_BOOL loggerConn_sendMsg (THandle loggerConn, PS8 buffer, U32 bufferSize);


#endif
