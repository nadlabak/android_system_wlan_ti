/*
 * log_common.h
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

/****************************************************************************/
/*                                                                          */
/*    MODULE:   CuCommon.h                                                  */
/*    PURPOSE:                                                              */
/*                                                                          */
/****************************************************************************/
#ifndef _CU_COMMON_H_
#define _CU_COMMON_H_

/* defines */
/***********/

/* types */
/*********/

/* functions */
/*************/
THandle CuCommon_Create(THandle *pIpcSta, const PS8 device_name);
VOID CuCommon_Destroy(THandle hCuCommon);

S32 CuCommon_SetBuffer(THandle hCuCommon, U32 PrivateIoctlId, PVOID pBuffer, U32 len);
S32 CuCommon_GetBuffer(THandle hCuCommon, U32 PrivateIoctlId, PVOID pBuffer, U32 len);

#endif  /* _CU_COMMON_H_ */
        
