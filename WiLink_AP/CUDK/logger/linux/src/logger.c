/*
 * logger.c
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
#include "ipc_event.h"
#include "ipc_sta.h"
#include "STADExternalIf.h"
#include "os_trans.h"

#include "log_conn.h"
#include "log_cmd.h"


U8 gdata[RPC_BUFFER_SIZE];

THandle hLogConn, IpcEvent;

void ProcessLoggerMessage(PU8 data, U32 len);
U8 LogMsg[MAX_MESSAGE_SIZE + MESSAGE_HEADER_SIZE];

/* HEX DUMP for BDs !!! Debug code only !!! */
void HexDumpData (PU8 data, TI_SIZE_T datalen)
{
#ifdef TI_DBG
TI_SIZE_T j, dbuflen=0;
S8 dbuf[50];
static S8 hexdigits[16] = "0123456789ABCDEF";

    for(j=0; j < datalen;)
    {
        /* Add a byte to the line*/
        dbuf[dbuflen] =  hexdigits[(data[j] >> 4)&0x0f];
        dbuf[dbuflen+1] = hexdigits[data[j] & 0x0f];
        dbuf[dbuflen+2] = ' ';
        dbuf[dbuflen+3] = '\0';
        dbuflen += 3;
        j++;
        if((j % 16) == 0)
        {
            /* Dump a line every 16 hex digits*/
            os_error_printf(CU_MSG_ERROR, "%04.4x  %s\n", j-16, dbuf);
            dbuflen = 0;
        }
    }
    /* Flush if something has left in the line*/
    if(dbuflen)
        os_error_printf(CU_MSG_ERROR, "%04.4x  %s\n", j & 0xfff0, dbuf);
#endif
}

void ProcessPacket(THandle CuCmd, PS8 input_string, S32 len)
{
    ConParm_t param;
    PS8 localInput_string;
    U16 numOfModules = len - REPORT_MODULES_OFFSET - 1;

    localInput_string = input_string;

    if(IS_MESSAGE_AFTER_CONNECT(localInput_string))
    { 
        localInput_string += MESSAGE_HEADER_SIZE;
    } 

    if(localInput_string[0] != MSG_PREFIX) {
        os_error_printf(CU_MSG_ERROR, "Missing prefix. prefix=%d\n", localInput_string[0]);
        return;
    }

    switch (localInput_string[1]) {
    case '2':
        param.value = (U32)&localInput_string[2];
        CuCmd_ReportSeverityLevel(CuCmd, &param, REPORT_SEVERITY_MAX);
        
        if (numOfModules > 0)
        {
            param.value = (U32)&localInput_string[REPORT_MODULES_OFFSET];
            CuCmd_AddReport(CuCmd, &param,  numOfModules );
        }
        break;
    case '3':
    case '4':
    case '5':
        os_error_printf(CU_MSG_ERROR, "%s: CMD_DEBUG. code=%c(0x%X)\n", __FUNCTION__, localInput_string[2], localInput_string[2]);
        break;
    default:
        os_error_printf(CU_MSG_ERROR, "%s: Unknown debug code (0x%X)\n", __FUNCTION__, localInput_string[2]);
        break;
    }
}

static TI_BOOL EnableLoggerEvent(THandle CuCmd, PU8 lastSevrityTable)
{
    ConParm_t param;
    IpcEvent = NULL;
    U8 logger_welcome_message[] = {'W', 2, 0, 2, 200};
    S32 appId;


    IpcEvent = IpcEvent_Create();
    if(IpcEvent == NULL)
        return FALSE;

    param.value = (U32)lastSevrityTable;
    CuCmd_ReportSeverityLevel(CuCmd, &param, REPORT_SEVERITY_MAX);

    if(IpcEvent_EnableEvent(IpcEvent, IPC_EVENT_LOGGER) == EOALERR_IPC_EVENT_ERROR_EVENT_ALREADY_ENABLED)
    {
        IpcEvent_Destroy(IpcEvent);
        return FALSE;
    }
    
    loggerConn_sendMsg(hLogConn, (PS8)logger_welcome_message, sizeof(logger_welcome_message)); /*eran - if we fail sending hello, what next?*/

    appId = IpcEvent_GetProcess(IpcEvent);
    /*Enable Logger output in driver */
    CuCmd_EnableLogger(CuCmd, appId);

    return TRUE;
}

static VOID DisbleLoggerEvent(THandle CuCmd)
{
    CuCmd_DisableLogger(CuCmd);

    IpcEvent_DisableEvent(IpcEvent, IPC_EVENT_LOGGER);
    IpcEvent_Destroy(IpcEvent);
}

void user_main(VOID)
{
#ifdef ETH_SUPPORT
    TLoggerConnParams LogConnParms;
    TI_SIZE_T sres;   
#endif
    THandle CuCmd;
    TI_BOOL rc;
   
    U8 lastSeverityTable[REPORT_SEVERITY_MAX];
    
    os_memset(lastSeverityTable, '0', REPORT_SEVERITY_MAX);
     
    CuCmd = CuCmd_Create(DEVICE_NAME, NULL, TRUE, "");
    if(CuCmd == NULL) {
        os_error_printf(CU_MSG_ERROR, "%s: Failed to create object. code=%d\n", __FUNCTION__, os_get_last_error());
        return;
    }

    rc = os_trans_create();
    if(!rc) {
        os_error_printf(CU_MSG_ERROR, "%s: os_trans_create failed code=%d\n", __FUNCTION__, os_get_last_error());
        return;
    }

#ifdef ETH_SUPPORT

    hLogConn = loggerConn_Create();
    LogConnParms.port_num = LOGGER_DEFAULT_PORT;

    rc = loggerConn_init(hLogConn, 0, &LogConnParms);
    if(!rc)
        return;

    do
    {
        rc = loggerConn_waitForConn(hLogConn);
        if(rc) 
        {
            if ( !EnableLoggerEvent(CuCmd, lastSeverityTable) )
            {
                os_error_printf(CU_MSG_ERROR, "%s: failed to init child process \n", __FUNCTION__);
            }
            else
            {
                do 
                {
                    sres = os_sockRecv( ((PLOG_CONN_DATA)hLogConn)->data_sock, gdata, sizeof(gdata), 0);
                    if(sres && (sres != SOCKET_ERROR) && (sres > REPORT_MODULES_OFFSET + 2)) 
                    {
                        os_memcpy(lastSeverityTable, gdata+2, REPORT_SEVERITY_MAX);
                        ProcessPacket(CuCmd, (PS8)gdata+2, sres-2);
                    }
                } while(sres && (sres != SOCKET_ERROR));
                DisbleLoggerEvent(CuCmd);
            }
        }
        else 
        {
            os_error_printf(CU_MSG_ERROR, "%s: socket error Error %d. Disconnecting...\n", __FUNCTION__, os_get_last_error());
        }
    }while(1);

#endif

}

/* Child functions */

void ProcessLoggerMessage(PU8 data, U32 len)
{
    U32 data_len = len + MESSAGE_HEADER_SIZE;
    if (len > MAX_MESSAGE_SIZE - 1)
        return;

    os_memset(LogMsg,0,sizeof(LogMsg));

    LogMsg[0] = 'W';  /* Ethernet protocol Prefix */
    LogMsg[1] = (unsigned char)((data_len-3) & 0xFF);          /* Message size (first byte) */ 
    LogMsg[2] = (unsigned char)(((data_len-3) >> 8) & 0xFF);   /* Message size (second byte) */
    /* Mark that this is log message */ 
    LogMsg[3] = 0;
    LogMsg[4] = 0;
    LogMsg[5] = 0;

    os_memcpy(&LogMsg[MESSAGE_HEADER_SIZE], data, len);

    /* Put '0' in the end of the string */
    LogMsg[data_len] = 0;

    if(!loggerConn_sendMsg(hLogConn, (PS8)LogMsg, data_len)) 
    {
        /*IpcEvent_DisableEvent(IpcEvent, IPC_EVENT_LOGGER); eran - not sure that child should do that*/
        os_error_printf(CU_MSG_ERROR, "%s: logger disconnected. disable IPC_EVENT_LOGGER\n", __FUNCTION__);
        return;
    }
}

VOID g_tester_send_event(U8 event_index)
{

}
