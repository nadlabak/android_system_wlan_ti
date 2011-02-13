/*
 * log_common.c
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
*   MODULE:  CU_Common.c
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
#include "ipc_sta.h"
#include "log_common.h"

/* defines */
/***********/

#define ECUERR_CU_COMMON_ERROR -1
#define ECUERR_CU_ERROR -1

/* local types */
/***************/
/* Module control block */
typedef struct CuCommon_t
{
    THandle hIpcSta;
} CuCommon_t;

/* local variables */
/*******************/

/* local fucntions */
/*******************/


/* functions */
/*************/
THandle CuCommon_Create(THandle *pIpcSta, const PS8 device_name)
{
    CuCommon_t* pCuCommon = (CuCommon_t*)os_MemoryCAlloc(sizeof(CuCommon_t), sizeof(U8));
    if(pCuCommon == NULL)
    {
        os_error_printf(CU_MSG_ERROR, (PS8)("ERROR - CuCommon_Create - cant allocate control block\n") );
        return NULL;
    }

    pCuCommon->hIpcSta = IpcSta_Create(device_name);
    if(pCuCommon->hIpcSta == NULL)
    {   
        CuCommon_Destroy(pCuCommon);
        return NULL;
    }
    *pIpcSta = pCuCommon->hIpcSta;

    return pCuCommon;
}

VOID CuCommon_Destroy(THandle hCuCommon)
{
    CuCommon_t* pCuCommon = (CuCommon_t*)hCuCommon;

    if(pCuCommon->hIpcSta)
        IpcSta_Destroy(pCuCommon->hIpcSta);

    os_MemoryFree(pCuCommon);
}

S32 CuCommon_SetBuffer(THandle hCuCommon, U32 PrivateIoctlId, PVOID pBuffer, U32 len)
{
    CuCommon_t* pCuCommon = (CuCommon_t*)hCuCommon; 
    S32 res;

    res = IPC_STA_Private_Send(pCuCommon->hIpcSta, PrivateIoctlId, pBuffer, len, 
                                                NULL, 0);

    if(res == EOALERR_IPC_STA_ERROR_SENDING_WEXT)
        return ECUERR_CU_COMMON_ERROR;

    return OK;      
}

S32 CuCommon_GetBuffer(THandle hCuCommon, U32 PrivateIoctlId, PVOID pBuffer, U32 len)
{
    CuCommon_t* pCuCommon = (CuCommon_t*)hCuCommon; 
    S32 res;

    res = IPC_STA_Private_Send(pCuCommon->hIpcSta, PrivateIoctlId, NULL, 0, 
                                                pBuffer, len);

    if(res == EOALERR_IPC_STA_ERROR_SENDING_WEXT)
        return ECUERR_CU_COMMON_ERROR;

    return OK;      
}










