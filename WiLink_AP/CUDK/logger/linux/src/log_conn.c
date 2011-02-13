/*
 * log_conn.c
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

#include "cu_osapi.h"
#include "os_trans.h"
#include "log_conn.h"
#include "STADExternalIf.h"

static LOG_CONN_DATA LogConn;

THandle loggerConn_Create()
{
	LogConn.listen_sock = NULL;
	LogConn.data_sock = NULL;
	LogConn.connections = 0;

	return (THandle) &LogConn;
}


TI_BOOL loggerConn_init (THandle loggerConn, 
					 ELoggerConnMedia mediaType,		/*currently unused */
					 TLoggerConnParams* mediaParams
					 )
{
	PLOG_CONN_DATA LogConn = (PLOG_CONN_DATA) loggerConn;
	TI_BOOL rc;

	rc = os_socket(&LogConn->listen_sock);
	if(!rc) {
		return(FALSE);
	}

	LogConn->data_sock = NULL;

	rc = os_bind(LogConn->listen_sock, mediaParams->port_num);
	if(!rc) {
		return(FALSE);
	}

	return TRUE;
}


TI_BOOL loggerConn_waitForConn (THandle loggerConn)
{
	PLOG_CONN_DATA LogConn = (PLOG_CONN_DATA) loggerConn;
	TI_BOOL rc;
	
	rc = os_sockWaitForConnection(LogConn->listen_sock, &LogConn->data_sock);

	if(!rc)
		return FALSE;

	LogConn->connections++;
	return TRUE;
}


TI_BOOL loggerConn_sendMsg (THandle loggerConn, PS8 buffer, U32 bufferSize)
{
	PLOG_CONN_DATA LogConn = (PLOG_CONN_DATA) loggerConn;
	if(LogConn->data_sock == NULL)
    {
        os_error_printf(CU_MSG_ERROR, "**** ERROR LogConn->data_sock is NULL ****\n");    
        return FALSE;
    }

	return os_sockSend(LogConn->data_sock, buffer, bufferSize);
}


VOID loggerConn_destroy (THandle loggerConn)
{
	PLOG_CONN_DATA LogConn = (PLOG_CONN_DATA) loggerConn;

	LogConn->listen_sock = NULL;
	LogConn->data_sock = NULL;

	LogConn->connections = 0;
}
