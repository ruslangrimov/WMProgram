#ifndef _NTINCLUDE_H_
#define _NTINCLUDE_H_

typedef unsigned short      WORD;
typedef unsigned char      BYTE;
typedef PVOID* PNTPROC;
typedef DWORD (ULONG);
typedef DWORD* PDWORD;
typedef BYTE* PBYTE;

typedef struct _LPC_SECTION_OWNER_MEMORY
 {
 ULONG Length;
 HANDLE SectionHandle;
 ULONG OffsetInSection;
 ULONG ViewSize;
 PVOID ViewBase;
 PVOID OtherSideViewBase;
 }
LPC_SECTION_OWNER_MEMORY, *PLPC_SECTION_OWNER_MEMORY;

typedef struct _LPC_SECTION_MEMORY
 {
 ULONG Length;
 ULONG ViewSize;
 PVOID ViewBase;
 }
LPC_SECTION_MEMORY, *PLPC_SECTION_MEMORY;

typedef struct _MY_PORT_MESSAGE
 {
 USHORT DataLength;                  // Length of data following the header (bytes)
 USHORT TotalLength;                 // Length of data + sizeof(PORT_MESSAGE)
 USHORT Type;                        // Type of the message (See LPC_TYPE enum)
 USHORT VirtualRangesOffset;         // Offset of array of virtual address ranges
 CLIENT_ID ClientId;                 // Client identifier of the message sender
 ULONG  MessageId;                   // Identifier of the particular message instance
 union
  {
  ULONG  CallbackId;                 //
  ULONG  ClientViewSize;             // Size, in bytes, of section created by the sender
  };
 ULONG param1;
 ULONG result;
 ULONG param2;
 char data[0x010c];
 }
MYPORT_MESSAGE, *PMYPORT_MESSAGE;

typedef USHORT SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

 typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemNotImplemented1,
    SystemProcessesAndThreadsInformation,
    SystemCallCounts,
    SystemConfigurationInformation,
    SystemProcessorTimes,
    SystemGlobalFlag,
    SystemNotImplemented2,
    SystemModuleInformation,
    SystemLockInformation,
    SystemNotImplemented3,
    SystemNotImplemented4,
    SystemNotImplemented5,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPagefileInformation,
    SystemInstructionEmulationCounts,
    SystemInvalidInfoClass1,
    SystemCacheInformation,
    SystemPoolTagInformation,
    SystemProcessorStatistics,
    SystemDpcInformation,
    SystemNotImplemented6,
    SystemLoadImage,
    SystemUnloadImage,
    SystemTimeAdjustment,
    SystemNotImplemented7,
    SystemNotImplemented8,
    SystemNotImplemented9,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemLoadAndCallImage,
    SystemPrioritySeparation,
    SystemNotImplemented10,
    SystemNotImplemented11,
    SystemInvalidInfoClass2,
    SystemInvalidInfoClass3,
    SystemTimeZoneInformation,
    SystemLookasideInformation,
    SystemSetTimeSlipEvent,
    SystemCreateSession,
    SystemDeleteSession,
    SystemInvalidInfoClass4,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS;

typedef struct _IMAGE_EXPORT_DIRECTORY {
 ULONG Characteristics;
 ULONG TimeDateStamp;
 WORD MajorVersion;
 WORD MinorVersion;
 ULONG Name;
 ULONG Base;
 ULONG NumberOfFunctions;
 ULONG NumberOfNames;
 ULONG AddressOfFunctions;
 ULONG AddressOfNames;
 ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

typedef struct _OBJECT_DIRECTORY_ENTRY *POBJECT_DIRECTORY_ENTRY;
typedef struct _OBJECT_DIRECTORY *POBJECT_DIRECTORY;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
     POBJECT_DIRECTORY_ENTRY ChainLink;
     PVOID Object;
     ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _DEVICE_MAP
{
     POBJECT_DIRECTORY DosDevicesDirectory;
     POBJECT_DIRECTORY GlobalDosDevicesDirectory;
     ULONG ReferenceCount;
     ULONG DriveMap;
     UCHAR DriveType[32];
} DEVICE_MAP, *PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY
{
     POBJECT_DIRECTORY_ENTRY HashBuckets[37];
     EX_PUSH_LOCK Lock;
     PDEVICE_MAP DeviceMap;
     ULONG SessionId;
     PVOID NamespaceEntry;
     ULONG Flags;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _OBJECT_HEADER_NAME_INFO {
    POBJECT_DIRECTORY Directory;
    UNICODE_STRING Name;
    ULONG Reserved;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;


typedef struct _OBJECT_HEADER {
    LONG PointerCount;
    union {
        LONG HandleCount;
        PSINGLE_LIST_ENTRY SEntry;
    };
    POBJECT_TYPE Type;
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;
    union {
        PVOID ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _MY_KEY_VALUE_PARTIAL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1024];            // Variable size
} MY_KEY_VALUE_PARTIAL_INFORMATION, *PMY_KEY_VALUE_PARTIAL_INFORMATION;

typedef struct _PDO_LIST {
 ULONG Flag;
 PDEVICE_OBJECT DeviceObject;
 ULONG Characteristics;
} *PPDO_LIST;

typedef struct _KEYBOARD_INPUT_DATA {
  USHORT  UnitId;
  USHORT  MakeCode;
  USHORT  Flags;
  USHORT  Reserved;
  ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

typedef struct MOUSE_INPUT_DATA {
  USHORT  UnitId;
  USHORT  Flags;
  union {
    ULONG  Buttons;
      struct {
         USHORT  ButtonFlags;
         USHORT  ButtonData;
      };
  };
  ULONG  RawButtons;
  LONG  LastX;
  LONG  LastY;
  ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;

typedef struct _LPC_MESSAGE {
  USHORT                  DataLength;
  USHORT                  Length;
  USHORT                  MessageType;
  USHORT                  DataInfoOffset;
  CLIENT_ID               ClientId;
  ULONG                   MessageId;
  ULONG                   CallbackId;
  BYTE                    *Data;
} LPC_MESSAGE, *PLPC_MESSAGE;

typedef struct
{
    ULONG  U1;
    ULONG  U2;
    ULONG  U3;
    ULONG  U4;
    ULONG  U5;
    ULONG  U6;
} CSRSS_STUB, *PCSRSS_STUB;

typedef struct
{
    ULONG  Flags;
    ULONG  Reserved;
} CSRSS_EXIT_OS, *PCSRSS_EXIT_OS;

#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T

typedef struct _CSR_API_MESSAGE
{
    PORT_MESSAGE Header;
    PVOID CsrCaptureData;
    ULONG Type;
    NTSTATUS Status;
    union
    {
    CSRSS_EXIT_OS ExitOsRequest;
    CSRSS_STUB Stub;
    } Data;
} CSR_API_MESSAGE, *PCSR_API_MESSAGE;

#define NUMBER_HASH_BUCKETS 37

#define OBJECT_TO_OBJECT_HEADER(o) CONTAINING_RECORD((o), OBJECT_HEADER, Body);

#define OBJECT_HEADER_TO_NAME_INFO( oh ) ((POBJECT_HEADER_NAME_INFO) \
    ((oh)->NameInfoOffset == 0 ? NULL : ((PCHAR)(oh) - (oh)->NameInfoOffset)))

  NTKERNELAPI
  ULONG
  PsGetCurrentProcessSessionId (
    VOID
  );

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeSid (
    IN OUT PSID                     Sid,
    IN PSID_IDENTIFIER_AUTHORITY    IdentifierAuthority,
    IN UCHAR                        SubAuthorityCount
);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId (
    IN PVOID        ProcessId,
    OUT PEPROCESS   *Process
);

NTKERNELAPI
PPEB
PsGetProcessPeb (
    PEPROCESS
);

NTSTATUS
ObOpenObjectByName(POBJECT_ATTRIBUTES ObjectAttributes,
     POBJECT_TYPE ObjectType,
     PVOID ParseContext,
     KPROCESSOR_MODE AccessMode,
     ACCESS_MASK DesiredAccess,
     PACCESS_STATE PassedAccessState,
     PHANDLE Handle);

NTSYSAPI
ULONG
NTAPI
RtlRandomEx (
    IN PULONG Seed
);

NTSTATUS
ZwQueryInformationProcess(
    IN HANDLE  ProcessHandle,
    IN PROCESSINFOCLASS  ProcessInformationClass,
    OUT PVOID  ProcessInformation,
    IN ULONG  ProcessInformationLength,
    OUT PULONG  ReturnLength
 );

NTSTATUS
ZwClearEvent (
    IN HANDLE EventHandle
);

/*  NTSYSAPI
         ULONG
         NTAPI
         ZwConnectPort(
   OUT PHANDLE             ClientPortHandle,
   IN PUNICODE_STRING      ServerPortName,
   IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
   IN OUT PLPC_SECTION_OWNER_MEMORY ClientSharedMemory OPTIONAL,
   OUT PLPC_SECTION_MEMORY ServerSharedMemory OPTIONAL,
   OUT PULONG              MaximumMessageLength OPTIONAL,
   IN PVOID                ConnectionInfo OPTIONAL,
   IN PULONG               ConnectionInfoLength OPTIONAL );
*/
#endif