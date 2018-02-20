#ifndef _DRIVER_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
#define _DRIVER_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
//----------------------------------------------------------------------------------------------------
// (Файл driver.h)
// Заголовочный файл Главного устройства
//----------------------------------------------------------------------------------------------------

#include <ntifs.h>
#include "..\ntinclude.h"
#include "..\ioctlcodes.h"
#include "..\general.h"
#include "aes_algoritm.h"
#include "ntcallhooks.h"

//----------------------------------------------------------------------------------------------------
//Описания для таблицы системных сервисов NT
//----------------------------------------------------------------------------------------------------
typedef struct _SYSTEM_SERVICE_TABLE
 {
 PNTPROC ServiceTable;
 PDWORD  CounterTable;
 ULONG   ServiceLimit;
 PBYTE   ArgumentTable;
 }
SYSTEM_SERVICE_TABLE ,
* PSYSTEM_SERVICE_TABLE ,
* * PPSYSTEM_SERVICE_TABLE ;

typedef struct _SERVICE_DESCRIPTOR_TABLE
 {
 SYSTEM_SERVICE_TABLE ntoskrnl;  //SST для ntoskrnl.exe
 SYSTEM_SERVICE_TABLE win32k;    //SST для win32k.sys
 SYSTEM_SERVICE_TABLE unused1;   //не используется
 SYSTEM_SERVICE_TABLE unused2;   //не используется
 }
SERVICE_DESCRIPTOR_TABLE ,
* PSERVICE_DESCRIPTOR_TABLE,
* * PPSERVICE_DESCRIPTOR_TABLE ;

//макрос для простого доступа к SST ядра
#define NTCALL(_function) KeServiceDescriptorTable->ntoskrnl.ServiceTable[_function]

//импортируем указатель на SDT
extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
//импортируем версию ядра NT
extern PUSHORT NtBuildNumber;

//----------------------------------------------------------------------------------------------------
//Экспортируемые переменные и функции
//----------------------------------------------------------------------------------------------------
PCHAR GetProcessName();
ULONG IsProgSession(ULONG SessionId);
PVOID SearchObject(PUNICODE_STRING pUni);
PDRIVER_DEVICE_EXTENSION GetDx();
ULONG CanShutdown();
NTSTATUS GetVideoDeviceInfo(PVIDEO_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx);
NTSTATUS GetInputDeviceInfo(PINPUT_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx, INPUT_DEVICE_TYPE InputType);
NTSTATUS GetHIDDeviceInfo(PHID_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx);
VOID CreateSessionThread(IN PVOID dx);
NTSTATUS CreateShutdownLink();
NTSTATUS GetAESKey(BYTE * buf);
NTSTATUS UpdateHidsPDO(PDRIVER_DEVICE_EXTENSION dx);
int __stdcall arrarr(BYTE *m1, ULONG s1, BYTE *m2, ULONG s2);

extern HANDLE WinlogonApiPort;
extern NtCreateEvent_PTR OldNtCreateEvent;
extern NtCreateDirectoryObject_PTR OldNtCreateDirectoryObject;
extern NtOpenFile_PTR OldNtOpenFile;
extern NtQueryInformationProcess_PTR OldNtQueryInformationProcess;
extern NtQueryInformationToken_PTR OldNtQueryInformationToken;
extern NtSetSystemInformation_PTR OldNtSetSystemInformation;
extern NtCreatePort_PTR OldNtCreatePort;
extern NtCreateFile_PTR OldNtCreateFile;
extern NtQueryValueKey_PTR OldNtQueryValueKey;
extern NtSetValueKey_PTR OldNtSetValueKey;
extern NtRequestWaitReplyPort_PTR OldNtRequestWaitReplyPort;
extern NtSecureConnectPort_PTR OldNtSecureConnectPort;
extern NtOpenDirectoryObject_PTR OldNtOpenDirectoryObject;

#endif

