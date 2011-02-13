/*
 * log_cmd.h
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
/*    MODULE:   cu_cmd.h                                                    */
/*    PURPOSE:                                                              */
/*                                                                          */
/****************************************************************************/
#ifndef _CU_CMD_H_
#define _CU_CMD_H_

/* defines */
/***********/
#define REPORT_MODULES_OFFSET           17
#define SEVERITY_MODULES_TABLE_OFFSET   2

/* types */
/*********/
typedef struct
{
    U32 value;
    PS8 name;
} named_value_t;

typedef enum
{
    E_OK = 0, 
    E_BADPARM, 
    E_TOOMANY,
    E_NOMEMORY,
    E_NOT_FOUND,
    E_EXISTS,
    E_DUMMY,
    E_ERROR
} consoleErr;

typedef struct ConParm_t
{
    PS8         name;                     /* Parameter name. Shouldn't be allocated on stack! */
    U8          flags;                    /* Combination of CON_PARM_??? flags */
    U32         low_val;                  /* Low val for range checking */
    U32         hi_val;                   /* Hi val for range checking/max length of string */
    U32         value;                    /* Value/address of string parameter */
} ConParm_t;

/* functions */
/*************/
THandle CuCmd_Create(const PS8 device_name, THandle hConsole, S32 BypassSupplicant, PS8 pSupplIfFile);

VOID CuCmd_Destroy(THandle hCuCmd);

VOID CuCmd_RegisterEvents(THandle hCuCmd, ConParm_t parm[], U16 nParms);
VOID CuCmd_UnregisterEvents(THandle hCuCmd, ConParm_t parm[], U16 nParms);

VOID CuCmd_AddReport(THandle hCuCmd, ConParm_t parm[], U16 nParms);
VOID CuCmd_ReportSeverityLevel(THandle hCuCmd, ConParm_t parm[], U16 nParms);


VOID CuCmd_EnableLogger(THandle hCuCmd, int appId);
VOID CuCmd_DisableLogger(THandle hCuCmd);


#endif  /* _CU_CMD_H_ */

