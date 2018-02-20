#ifndef _NTCALLHOOKS_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
#define _NTCALLHOOKS_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_

#include <stdio.h>

#include <ntifs.h>
#include "..\ntinclude.h"
#include "..\general.h"

//----------------------------------------------------------------------------------------------------
// Прототипы системных вызовов
//----------------------------------------------------------------------------------------------------
typedef NTSTATUS
  (*NtCreateEvent_PTR)(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN EVENT_TYPE  EventType,
    IN BOOLEAN  InitialState
    );

typedef NTSTATUS
  (*NtCreateDirectoryObject_PTR)(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS
  (*NtOpenFile_PTR)(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  ShareAccess,
    IN ULONG  OpenOptions
    );

typedef NTSTATUS
  (*NtQueryInformationProcess_PTR)(
    IN HANDLE  ProcessHandle,
    IN PROCESSINFOCLASS  ProcessInformationClass,
    OUT PVOID  ProcessInformation,
    IN ULONG  ProcessInformationLength,
    OUT PULONG  ReturnLength
    );

 typedef NTSTATUS
   (*NtQueryInformationToken_PTR)(
        IN HANDLE  TokenHandle,
        IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
        OUT PVOID  TokenInformation,
        IN ULONG  TokenInformationLength,
        OUT PULONG  ReturnLength
     );

  typedef NTSTATUS
   (*NtSetSystemInformation_PTR)(
     IN SYSTEM_INFORMATION_CLASS  SystemInformationClass,
     IN PVOID  SystemInformation,
     IN ULONG  SystemInformationLength
     );

  typedef NTSTATUS
   (*NtCreatePort_PTR)(
     OUT PHANDLE  PortHandle,
     IN POBJECT_ATTRIBUTES  ObjectAttributes,
     IN ULONG  MaxConnectInfoLength,
     IN ULONG  MaxDataLength,
     IN OUT PULONG  Reserved OPTIONAL
     );

typedef NTSTATUS
   (*NtCreateFile_PTR)(
     OUT PHANDLE  FileHandle,
     IN ACCESS_MASK  DesiredAccess,
     IN POBJECT_ATTRIBUTES  ObjectAttributes,
     OUT PIO_STATUS_BLOCK  IoStatusBlock,
     IN PLARGE_INTEGER  AllocationSize OPTIONAL,
     IN ULONG  FileAttributes,
     IN ULONG  ShareAccess,
     IN ULONG  CreateDisposition,
     IN ULONG  CreateOptions,
     IN PVOID  EaBuffer OPTIONAL,
     IN ULONG  EaLength
     );

typedef NTSTATUS
   (*NtQueryValueKey_PTR)(
     IN HANDLE  KeyHandle,
     IN PUNICODE_STRING  ValueName,
     IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
     OUT PMY_KEY_VALUE_PARTIAL_INFORMATION  KeyValueInformation,
     IN ULONG  Length,
     OUT PULONG  ResultLength
     );

typedef NTSTATUS
   (*NtSetValueKey_PTR)(
     IN HANDLE  KeyHandle,
     IN PUNICODE_STRING  ValueName,
     IN ULONG  TitleIndex OPTIONAL,
     IN ULONG  Type,
     IN PVOID  Data,
     IN ULONG  DataSize
     );

typedef NTSTATUS
   (*NtRequestWaitReplyPort_PTR)(
     IN HANDLE  PortHandle,
     IN PLPC_MESSAGE  Request,
     OUT PLPC_MESSAGE  IncomingReply
     );

typedef NTSTATUS
   (*NtSecureConnectPort_PTR)(
     OUT PHANDLE ConnectedPort,
     IN PUNICODE_STRING PortName,
     IN PSECURITY_QUALITY_OF_SERVICE Qos,
     IN OUT PPORT_VIEW WriteMap OPTIONAL,
     IN PSID ServerSid OPTIONAL,
     IN OUT PREMOTE_PORT_VIEW ReadMap OPTIONAL,
     OUT PULONG MaxMessageSize OPTIONAL,
     IN OUT PVOID ConnectInfo OPTIONAL,
     IN OUT PULONG UserConnectInfoLength OPTIONAL
     );

typedef NTSTATUS
  (*NtOpenDirectoryObject_PTR)(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

#define ACCESS_ALLOWED_ACE_TYPE         (0x0)

#define SECURITY_WORLD_SID_AUTHORITY    {0,0,0,0,0,1}

//----------------------------------------------------------------------------------------------------
// Коды системных вызовов
//----------------------------------------------------------------------------------------------------
#define SERVICE_ID_NtCreateEvent             35
#define SERVICE_ID_NtCreateDirectoryObject   34
#define SERVICE_ID_NtOpenFile                116
#define SERVICE_ID_NtQueryInformationProcess 154
#define SERVICE_ID_NtQueryInformationToken   156
#define SERVICE_ID_NtSetSystemInformation    240
#define SERVICE_ID_NtCreatePort              46
#define SERVICE_ID_NtCreateFile              37
#define SERVICE_ID_NtQueryValueKey           177
#define SERVICE_ID_NtSetValueKey             247
#define SERVICE_ID_NtRequestWaitReplyPort    200
#define SERVICE_ID_NtSecureConnectPort       210
#define SERVICE_ID_NtOpenDirectoryObject     113

//----------------------------------------------------------------------------------------------------
// Предопределение функций
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtCreateEvent(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN EVENT_TYPE  EventType,
    IN BOOLEAN  InitialState
 );

 NTSTATUS NewNtCreateDirectoryObject(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
 );

 NTSTATUS NewNtOpenFile(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  ShareAccess,
    IN ULONG  OpenOptions
 );

  NTSTATUS NewNtQueryInformationProcess(
    IN HANDLE  ProcessHandle,
    IN PROCESSINFOCLASS  ProcessInformationClass,
    OUT PVOID  ProcessInformation,
    IN ULONG  ProcessInformationLength,
    OUT PULONG  ReturnLength
 );

 NTSTATUS NewNtQueryInformationToken(
     IN HANDLE  TokenHandle,
     IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
     OUT PVOID  TokenInformation,
     IN ULONG  TokenInformationLength,
     OUT PULONG  ReturnLength
 );

 NTSTATUS NewNtSetSystemInformation(
     IN SYSTEM_INFORMATION_CLASS  SystemInformationClass,
     IN PSYSTEM_GDI_DRIVER_INFORMATION  SystemInformation,
     IN ULONG  SystemInformationLength
 );

 NTSTATUS NewNtCreatePort(
     OUT PHANDLE  PortHandle,
     IN POBJECT_ATTRIBUTES  ObjectAttributes,
     IN ULONG  MaxConnectInfoLength,
     IN ULONG  MaxDataLength,
     IN OUT PULONG  Reserved OPTIONAL
  );

NTSTATUS NewNtCreateFile(
     OUT PHANDLE  FileHandle,
     IN ACCESS_MASK  DesiredAccess,
     IN POBJECT_ATTRIBUTES  ObjectAttributes,
     OUT PIO_STATUS_BLOCK  IoStatusBlock,
     IN PLARGE_INTEGER  AllocationSize OPTIONAL,
     IN ULONG  FileAttributes,
     IN ULONG  ShareAccess,
     IN ULONG  CreateDisposition,
     IN ULONG  CreateOptions,
     IN PVOID  EaBuffer OPTIONAL,
     IN ULONG  EaLength
 );

NTSTATUS NewNtQueryValueKey(
     IN HANDLE  KeyHandle,
     IN PUNICODE_STRING  ValueName,
     IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
     OUT PMY_KEY_VALUE_PARTIAL_INFORMATION  KeyValueInformation,
     IN ULONG  Length,
     OUT PULONG  ResultLength
);

NTSTATUS NewNtSetValueKey(
     IN HANDLE  KeyHandle,
     IN PUNICODE_STRING  ValueName,
     IN ULONG  TitleIndex OPTIONAL,
     IN ULONG  Type,
     IN PVOID  Data,
     IN ULONG  DataSize
);

NTSTATUS NewNtRequestWaitReplyPort(
     IN HANDLE  PortHandle,
     IN PCSR_API_MESSAGE  Request,
     OUT PCSR_API_MESSAGE  IncomingReply
);

NTSTATUS NewNtSecureConnectPort(
     OUT PHANDLE ConnectedPort,
     IN PUNICODE_STRING PortName,
     IN PSECURITY_QUALITY_OF_SERVICE Qos,
     IN OUT PPORT_VIEW WriteMap OPTIONAL,
     IN PSID ServerSid OPTIONAL,
     IN OUT PREMOTE_PORT_VIEW ReadMap OPTIONAL,
     OUT PULONG MaxMessageSize OPTIONAL,
     IN OUT PVOID ConnectInfo OPTIONAL,
     IN OUT PULONG UserConnectInfoLength OPTIONAL
     );

 NTSTATUS NewNtOpenDirectoryObject(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
 );

#endif