/*
 * log_cmd.c
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

/****************************************************************************
*
*   MODULE:  log_cmd.c
*   
*   PURPOSE: 
* 
*   DESCRIPTION:  
*   ============
*      
*
****************************************************************************/

/* includes */
/************/

#include "cu_osapi.h"
#include "STADExternalIf.h"
#include "log_common.h"
#include "cu_os.h"
#include "ipc_event.h"
#include "log_cmd.h"

/* defines */
/***********/

#define CU_CMD_FIND_NAME_ARRAY(index, arr, val) \
        for ( index = 0; index < SIZE_ARR(arr); index++ ) \
            if ( arr[ index ].value == (val) ) \
                break; \

static named_value_t report_severity[] = {
    { 0,                          (PS8)"----"           },
    { REPORT_SEVERITY_INIT,         (PS8)"INIT",          },
    { REPORT_SEVERITY_INFORMATION,  (PS8)"INFORMATION",   },
    { REPORT_SEVERITY_WARNING,      (PS8)"WARNING",       },
    { REPORT_SEVERITY_ERROR,        (PS8)"ERROR",         },
    { REPORT_SEVERITY_FATAL_ERROR,  (PS8)"FATAL_ERROR",   },
    { REPORT_SEVERITY_SM,           (PS8)"SM",            },
    { REPORT_SEVERITY_CONSOLE,      (PS8)"CONSOLE",       },
};

/* local types */
/***************/

/* Module control block */
typedef struct CuCmd_t
{
    THandle                 hCuWext;
    THandle                 hCuCommon;
    THandle                 hConsole;
    THandle                 hIpcEvent;
    THandle                 hWpaCore;
    
    U32                     isDeviceRunning;

    TScanParams             appScanParams;
    TPeriodicScanParams     tPeriodicAppScanParams;
    TScanPolicy             scanPolicy;
    
} CuCmd_t;

/* local variables */
/*******************/

/* functions */
/*************/
THandle CuCmd_Create(const PS8 device_name, THandle hConsole, S32 BypassSupplicant, PS8 pSupplIfFile)
{
    THandle hIpcSta;

    CuCmd_t* pCuCmd = (CuCmd_t*)os_MemoryCAlloc(sizeof(CuCmd_t), sizeof(U8));
    if(pCuCmd == NULL)
    {
        os_error_printf(CU_MSG_ERROR, (PS8)"ERROR - CuCmd_Create - cant allocate control block\n");
        return NULL;
    }

    pCuCmd->isDeviceRunning = FALSE;
    pCuCmd->hConsole = hConsole;
    
    pCuCmd->hCuCommon= CuCommon_Create(&hIpcSta, device_name);
    if(pCuCmd->hCuCommon == NULL)
    {   
        CuCmd_Destroy(pCuCmd);
        return NULL;
    }

    pCuCmd->hCuWext= CuOs_Create(hIpcSta);
    if(pCuCmd->hCuWext == NULL)
    {   
        CuCmd_Destroy(pCuCmd);
        return NULL;
    }
#if 0
    pCuCmd->hIpcEvent = (THandle) IpcEvent_Create();
    if(pCuCmd->hIpcEvent == NULL)
    {   
        CuCmd_Destroy(pCuCmd);
        return NULL;
    }

    if(BypassSupplicant)
    {
        /* specify that there is no supplicant */
        pCuCmd->hWpaCore = NULL;
    }
    else
    {
/*#ifndef NO_WPA_SUPPL*/
        S32 res;

        pCuCmd->hWpaCore = WpaCore_Create(&res, pSupplIfFile);
        if((pCuCmd->hWpaCore == NULL) && (res != EOALERR_IPC_WPA_ERROR_CANT_CONNECT_TO_SUPPL))
        {
            CuCmd_Destroy(pCuCmd);
            return NULL;
        }

        if(res == EOALERR_IPC_WPA_ERROR_CANT_CONNECT_TO_SUPPL)
        {
            os_error_printf(CU_MSG_ERROR, (PS8)"******************************************************\n");
            os_error_printf(CU_MSG_ERROR, (PS8)"Connection to supplicant failed\n");
            os_error_printf(CU_MSG_ERROR, (PS8)"******************************************************\n");
        }
        else
        {
            os_error_printf(CU_MSG_INFO2, (PS8)"Connection established with supplicant\n");
        }
/*#endif*/
    }

    CuCmd_Init_Scan_Params(pCuCmd);
#endif
    return pCuCmd;
}

VOID CuCmd_Destroy(THandle hCuCmd)
{
    CuCmd_t* pCuCmd = (CuCmd_t*)hCuCmd;

    if(pCuCmd->hCuCommon)
    {
        CuCommon_Destroy(pCuCmd->hCuCommon);
    }

    if(pCuCmd->hCuWext)
    {
        CuOs_Destroy(pCuCmd->hCuWext);
    }

    if(pCuCmd->hIpcEvent)
    {
        IpcEvent_Destroy(pCuCmd->hIpcEvent);
    }

    os_MemoryFree(pCuCmd);
}

VOID CuCmd_AddReport(THandle hCuCmd, ConParm_t parm[], U16 nParms)
{
    CuCmd_t* pCuCmd = (CuCmd_t*)hCuCmd;
    U8 ModuleTable[REPORT_FILES_NUM], ModuleValue[REPORT_FILES_NUM] = {0};
    int index = 0;

    os_memcpy((THandle)ModuleValue, (THandle)(parm[0].value), nParms);

    for (index = 0; index < REPORT_FILES_NUM; index ++)
    {
        if (ModuleValue[index] == '1')
        {
            ModuleTable[index] = '1';
        } 
        else
        {
            ModuleTable[index] = '0';
        }
    }
    CuCommon_SetBuffer(pCuCmd->hCuCommon, REPORT_MODULE_TABLE_PARAM, ModuleTable, REPORT_FILES_NUM);
}

VOID CuCmd_ReportSeverityLevel(THandle hCuCmd, ConParm_t parm[], U16 nParms)
{
    CuCmd_t* pCuCmd = (CuCmd_t*)hCuCmd;
    U8 SeverityTable[REPORT_SEVERITY_MAX];
    S32 index = 0;
    PS8 SeverityValue = (PS8)(parm[0].value);

    /* Get the current report severity */
    if (!CuCommon_GetBuffer(pCuCmd->hCuCommon, REPORT_SEVERITY_TABLE_PARAM, SeverityTable, REPORT_SEVERITY_MAX))    
    {
        if(nParms == 0)
        {            
            S32 i;

            os_error_printf(CU_MSG_INFO2, (PS8)"Severity:\n");
            os_error_printf(CU_MSG_INFO2, (PS8)"-------------------------------\n");
            os_error_printf(CU_MSG_INFO2, (PS8)"%14s\tState\t%s\n", (PS8)"Severity level", (PS8)"Desc");

            for( i=1; i<SIZE_ARR(report_severity); i++ )
            {
                os_error_printf(CU_MSG_INFO2, (PS8)"%d\t%c\t%s\n", report_severity[i].value, (SeverityTable[i] == '1') ? '+' : ' ', report_severity[i].name );
            }

            os_error_printf(CU_MSG_INFO2, (PS8)"* Use '0' to clear all table.\n");
            os_error_printf(CU_MSG_INFO2, (PS8)"* Use '%d' (max index) to set all table.\n", REPORT_SEVERITY_MAX);            
        }
        else
        {
            for (index = 0; index < REPORT_SEVERITY_MAX; index ++)
            {
                if (SeverityValue[index] == '0')
                {
                    SeverityTable[index] = '0';
                } 
                else
                {
                    SeverityTable[index] = '1';
                }
            }
            CuCommon_SetBuffer(pCuCmd->hCuCommon, REPORT_SEVERITY_TABLE_PARAM, SeverityTable, REPORT_SEVERITY_MAX);
        }
    }
    else
    {
        os_error_printf(CU_MSG_ERROR, (PS8)"Error retriving the severity table from the driver\n");
    }
}


VOID CuCmd_EnableLogger(THandle hCuCmd, int appId)
{
    CuCmd_t* pCuCmd = (CuCmd_t*)hCuCmd;


    CuCommon_SetBuffer(pCuCmd->hCuCommon, REPORT_OUTPUT_TO_LOGGER_ON, (void*)&appId, sizeof(appId));
}

VOID CuCmd_DisableLogger(THandle hCuCmd)
{
    CuCmd_t* pCuCmd = (CuCmd_t*)hCuCmd;

    CuCommon_SetBuffer(pCuCmd->hCuCommon, REPORT_OUTPUT_TO_LOGGER_OFF, NULL, 0);
}
