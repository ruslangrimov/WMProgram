//---------------------------------------------------------------------------
//
//---------------------------------------------------------------------------
#include "Driver.h"

//Глобальные переменные
ULONG ProcessNameOffset;
HANDLE WinlogonApiPort;
NtCreateEvent_PTR OldNtCreateEvent;
NtCreateDirectoryObject_PTR OldNtCreateDirectoryObject;
NtOpenFile_PTR OldNtOpenFile;
NtQueryInformationProcess_PTR OldNtQueryInformationProcess;
NtQueryInformationToken_PTR OldNtQueryInformationToken;
NtSetSystemInformation_PTR OldNtSetSystemInformation;
NtCreatePort_PTR OldNtCreatePort;
NtCreateFile_PTR OldNtCreateFile;
NtQueryValueKey_PTR OldNtQueryValueKey;
NtSetValueKey_PTR OldNtSetValueKey;
NtRequestWaitReplyPort_PTR OldNtRequestWaitReplyPort;
NtSecureConnectPort_PTR OldNtSecureConnectPort;
NtOpenDirectoryObject_PTR OldNtOpenDirectoryObject;

// Предварительное объявление функций:
NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp );
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);
NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);

VOID __stdcall CreateSession(PDRIVER_DEVICE_EXTENSION dx);
ULONG GetProcessNameOffset();
PCHAR GetProcessName();
VOID HookNtCalls(PDRIVER_DEVICE_EXTENSION dx);
VOID UnHookNtCalls(PDRIVER_DEVICE_EXTENSION dx);
PVOID SearchObject(PUNICODE_STRING pUni);
ULONG CanShutdown();
NTSTATUS CreateShutdownLink();
NTSTATUS GetVideoDeviceInfo(PVIDEO_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx);
NTSTATUS GetInputDeviceInfo(PINPUT_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx, INPUT_DEVICE_TYPE InputType);
NTSTATUS GetHIDDeviceInfo(PHID_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx);
NTSTATUS GetSettings(PSETTINGS Settings, PDRIVER_DEVICE_EXTENSION dx);

#pragma code_seg("INIT") // начало секции INIT

//---------------------------------------------------------------------------
// Точка входа в драйвер Главного устройства
//---------------------------------------------------------------------------
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
 {
 NTSTATUS status = STATUS_SUCCESS;
 ULONG i;
 PDEVICE_OBJECT fdo = NULL;
 UNICODE_STRING devName;
 PDRIVER_DEVICE_EXTENSION dx = NULL;
 UNICODE_STRING symLinkName;
 UNICODE_STRING uWin32DriverName;
 OBJECT_ATTRIBUTES ObjectAttributes;
 HANDLE Handle;
 NTSTATUS status2;
 UNICODE_STRING uEventName;
 OBJECT_ATTRIBUTES EventAttributes;
 HANDLE Event;

 __try
  {
  #if DBG
   DbgPrint("M: In DriverEntry\n");
   DbgPrint("M: RegistryPath = %ws\n", RegistryPath->Buffer);
  #endif

  DriverObject->DriverUnload = UnloadRoutine;
  DriverObject->MajorFunction[IRP_MJ_CREATE]= Create_File_IRPprocessing;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close_HandleIRPprocessing;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]= DeviceControlRoutine;

  RtlInitUnicodeString(&devName, MAIN_DEVICE_NAME);
  status = IoCreateDevice(DriverObject, sizeof(DRIVER_DEVICE_EXTENSION), &devName,
   FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);

  if (! NT_SUCCESS(status))
   __leave;

  dx = (PDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
  dx->fdo = fdo;  // Обратный указатель
  #if DBG
   DbgPrint("M: FDO %X, DevExt=%X\n", fdo, dx);
  #endif

  // Формируем символьное имя
  wcscpy(dx->SymLinkNameBuf, MAIN_SYM_LINK_NAME);
  RtlInitUnicodeString( &symLinkName, dx->SymLinkNameBuf);

  dx->StartSettings = ExAllocatePoolWithTag(NonPagedPool, sizeof(SETTINGS), TAG);

  if (! dx->StartSettings)
   __leave;

  dx->SymLinkName = symLinkName;
  dx->InSessionStart = FALSE;
  for (i = 0; i < 10; i ++)
   dx->Sessions[i] = -1;
  dx->Sessions[0] = 0;
  dx->LastWorkstation = 0;

  for (i = 0; i < 10; i++)
   dx->IsLogged[i] = 0;

  // Создаем символьную ссылку
  status = IoCreateSymbolicLink( &symLinkName, &devName );
  if (! NT_SUCCESS(status))
   __leave;

  ProcessNameOffset = GetProcessNameOffset();

  dx->StartOnBoot = TRUE;
  RtlInitUnicodeString(&uWin32DriverName, L"\\Driver\\Win32k");
  InitializeObjectAttributes(&ObjectAttributes, &uWin32DriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status2 = ObOpenObjectByName(&ObjectAttributes, 0L, 0L, 0L, 0L, 0L, &Handle);
  DbgPrint("ObOpenObjectByName %X\n", status2);
  if (status2 == STATUS_SUCCESS)
   {
   dx->StartOnBoot = FALSE;
   ZwClose(Handle);
   }

  RtlZeroMemory(dx->NullSessionProcList, 1024);
  dx->EnableMultipleTSSessions = 0;
  dx->DisableHostDeviceCheck = 0;

  GetSettings(dx->StartSettings, dx);

  #if DBG
   DbgPrint("M: NullSessionProcList %s\n", dx->NullSessionProcList);
  #endif

  //Бредятина, чтобы сбить команды при дизассамблировании
  if (dx->StartSettings->WorkstationsCount > 100)
   {
   _asm
    {
    _emit 0x4A
    _emit 0xA2
    _emit 0x12
    _emit 0x78
    _emit 0x01
    _emit 0x02
    _emit 0x07
    _emit 0xA2
    }
   }
  //

  dx->IsRegisterCopy = 0;

  dx->HaveAllConsoleDevices = 0;

  #if DEMO

  #else
   if (!dx->StartOnBoot) //если не стартует при загрузке, то выполним проверку секретного кода здесь
    {
    //расшифровка кода
    int Nr = 256;
    int Nk = Nr / 32;
    unsigned char Key[32] = {0};
    unsigned char RoundKey[240];
    unsigned char out[SECR_CODE_SIZE] = {0};
    ULONG i;
    ULONG filesize;
    ULONG src;
    ULONG * out32 = (ULONG *)out;

    Nr = Nk + 6;

    status = GetAESKey(Key);
    if (status == STATUS_SUCCESS)
     {
     KeyExpansion(Nk, Nr, RoundKey, Key, Rcon);
     for (i = 0; i < SECR_CODE_SIZE; i += 16)
      InvCipher(Nr, &dx->StartSettings->Data[i], &out[i], RoundKey);

     filesize = out32[SECR_CODE_SIZE / 4 - 1];

     src = 0;
     if (filesize < SECR_CODE_SIZE)
      {
      for (i = 0; i < filesize; i ++)
       src += (BYTE)out[i];
      }
     //конец расшифровки

     if (out32[SECR_CODE_SIZE / 4 - 3] == VERSION)
      {
      if ((filesize < SECR_CODE_SIZE) && (src == out32[SECR_CODE_SIZE / 4 - 2]))
       {
       dx->IsRegisterCopy = 1;
       }
      }
     }
    }
  #endif

  RtlInitUnicodeString(&uEventName, CANCLOSE_EVENT_NAME);
  InitializeObjectAttributes(&EventAttributes, &uEventName , 0, NULL, NULL);
  status2 = ZwCreateEvent(&Event, STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x03, &EventAttributes, NotificationEvent,
   FALSE);

  #if DBG
   DbgPrint("M: ZwCreateEvent CANCLOSE_EVENT_NAME = %X\n", status);
  #endif

  RtlInitUnicodeString(&uEventName, WAIT_ANSWERS_CANCLOSE_EVENT_NAME);
  InitializeObjectAttributes(&EventAttributes, &uEventName , 0, NULL, NULL);
  status2 = ZwCreateEvent(&Event, STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x03, &EventAttributes, NotificationEvent,
   FALSE);

  #if DBG
   DbgPrint("M: ZwCreateEvent WAIT_ANSWERS_CANCLOSE_EVENT_NAME = %X\n", status);
  #endif

  dx->TotalCanContinueShutdown = FALSE;
  dx->SessionsStarted = FALSE;

  //Перехватываем системные вызовы
  if (dx->StartOnBoot)
   HookNtCalls(dx);

  }

 __finally
  {
  if (! NT_SUCCESS(status))
   {
   if (fdo)
    {
    if (dx->StartSettings)
     ExFreePool(dx->StartSettings);

    IoDeleteDevice(fdo);
    }
   }
  }

 return status;
 }

#pragma code_seg() // end INIT section

#pragma code_seg("PAGE")
//----------------------------------------------------------------------------------------------------
// Нипоняяятная функция
//----------------------------------------------------------------------------------------------------
ULONG GetProcessNameOffset()
 {
 PEPROCESS curproc;
 int i;
 curproc = IoGetCurrentProcess();
 for(i = 0; i < 3 * PAGE_SIZE; i++)
  {
  if(! _stricmp("System", (PCHAR)curproc + i))
   {
   return i;
   }
  }
 return 0;
 }

//----------------------------------------------------------------------------------------------------
// Функция для получения имени процесса
//----------------------------------------------------------------------------------------------------
PCHAR GetProcessName()
 {
 PEPROCESS CurrentProcess;
 PCHAR ProcessName = NULL;
 if(ProcessNameOffset != 0)
  {
  CurrentProcess = IoGetCurrentProcess();
  ProcessName = (PCHAR)CurrentProcess + ProcessNameOffset;
  }
 return ProcessName;
 }
//----------------------------------------------------------------------------------------------------
// Функция переопределения системных вызовов
//----------------------------------------------------------------------------------------------------
VOID HookNtCalls(PDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG CR0Reg;

 dx->OrigFuncNtCreateEvent = (NtCreateEvent_PTR) NTCALL(SERVICE_ID_NtCreateEvent);
 OldNtCreateEvent = dx->OrigFuncNtCreateEvent;
 dx->OrigFuncNtCreateDirectoryObject = (NtCreateDirectoryObject_PTR) NTCALL(SERVICE_ID_NtCreateDirectoryObject);
 OldNtCreateDirectoryObject = dx->OrigFuncNtCreateDirectoryObject;
 dx->OrigFuncNtOpenFile = (NtOpenFile_PTR) NTCALL(SERVICE_ID_NtOpenFile);
 OldNtOpenFile = dx->OrigFuncNtOpenFile;
 dx->OrigFuncNtQueryInformationProcess = (NtQueryInformationProcess_PTR) NTCALL(SERVICE_ID_NtQueryInformationProcess);
 OldNtQueryInformationProcess= dx->OrigFuncNtQueryInformationProcess;
 dx->OrigFuncNtQueryInformationToken = (NtQueryInformationToken_PTR) NTCALL(SERVICE_ID_NtQueryInformationToken);
 OldNtQueryInformationToken = dx->OrigFuncNtQueryInformationToken;
 dx->OrigFuncNtSetSystemInformation = (NtSetSystemInformation_PTR) NTCALL(SERVICE_ID_NtSetSystemInformation);
 OldNtSetSystemInformation = dx->OrigFuncNtSetSystemInformation;
 dx->OrigFuncNtCreatePort = (NtCreatePort_PTR) NTCALL(SERVICE_ID_NtCreatePort);
 OldNtCreatePort = dx->OrigFuncNtCreatePort;
 dx->OrigFuncNtCreateFile = (NtCreateFile_PTR) NTCALL(SERVICE_ID_NtCreateFile);
 OldNtCreateFile = dx->OrigFuncNtCreateFile;
 dx->OrigFuncNtQueryValueKey = (NtQueryValueKey_PTR) NTCALL(SERVICE_ID_NtQueryValueKey);
 OldNtQueryValueKey = dx->OrigFuncNtQueryValueKey;
 dx->OrigFuncNtSetValueKey = (NtSetValueKey_PTR) NTCALL(SERVICE_ID_NtSetValueKey);
 OldNtSetValueKey = dx->OrigFuncNtSetValueKey;
 dx->OrigFuncNtRequestWaitReplyPort = (NtRequestWaitReplyPort_PTR) NTCALL(SERVICE_ID_NtRequestWaitReplyPort);
 OldNtRequestWaitReplyPort = dx->OrigFuncNtRequestWaitReplyPort;
 dx->OrigFuncNtSecureConnectPort = (NtSecureConnectPort_PTR) NTCALL(SERVICE_ID_NtSecureConnectPort);
 OldNtSecureConnectPort = dx->OrigFuncNtSecureConnectPort;
 dx->OrigFuncNtOpenDirectoryObject = (NtOpenDirectoryObject_PTR) NTCALL(SERVICE_ID_NtOpenDirectoryObject);
 OldNtOpenDirectoryObject = dx->OrigFuncNtOpenDirectoryObject;

 __asm
  {
  cli                     // запрещаем прерывания
  mov eax, cr0
  mov CR0Reg,eax
  and eax, 0xFFFEFFFF  // сбросить WP bit
  mov cr0, eax
  }

 NTCALL(SERVICE_ID_NtCreateEvent) = NewNtCreateEvent;
 NTCALL(SERVICE_ID_NtCreateDirectoryObject) = NewNtCreateDirectoryObject;
 NTCALL(SERVICE_ID_NtOpenFile) = NewNtOpenFile;
 NTCALL(SERVICE_ID_NtQueryInformationProcess) = NewNtQueryInformationProcess;
 NTCALL(SERVICE_ID_NtQueryInformationToken) = NewNtQueryInformationToken;
 NTCALL(SERVICE_ID_NtSetSystemInformation) = NewNtSetSystemInformation;
 NTCALL(SERVICE_ID_NtCreatePort) = NewNtCreatePort;
 NTCALL(SERVICE_ID_NtCreateFile) = NewNtCreateFile;
 NTCALL(SERVICE_ID_NtQueryValueKey) = NewNtQueryValueKey;
 NTCALL(SERVICE_ID_NtSetValueKey) = NewNtSetValueKey;
 NTCALL(SERVICE_ID_NtRequestWaitReplyPort) = NewNtRequestWaitReplyPort;
 NTCALL(SERVICE_ID_NtSecureConnectPort) = NewNtSecureConnectPort;
 NTCALL(SERVICE_ID_NtOpenDirectoryObject) = NewNtOpenDirectoryObject;

 __asm
  {
  mov eax, CR0Reg
  mov cr0, eax            // востановить содержимое CR0
  sti                     // разрешаем прерывания
  }

 }

//----------------------------------------------------------------------------------------------------
// Функция восстановления исходных системных вызовов
//----------------------------------------------------------------------------------------------------
VOID UnHookNtCalls(PDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG CR0Reg;

 __asm
  {
  cli;
  mov eax, cr0
  mov CR0Reg,eax
  and eax,0xFFFEFFFF  // сбросить WP bit
  mov cr0, eax
  }

 NTCALL(SERVICE_ID_NtCreateEvent) = dx->OrigFuncNtCreateEvent;
 NTCALL(SERVICE_ID_NtCreateDirectoryObject) = dx->OrigFuncNtCreateDirectoryObject;
 NTCALL(SERVICE_ID_NtOpenFile) = dx->OrigFuncNtOpenFile;
 NTCALL(SERVICE_ID_NtQueryInformationProcess) = dx->OrigFuncNtQueryInformationProcess;
 NTCALL(SERVICE_ID_NtQueryInformationToken) = dx->OrigFuncNtQueryInformationToken;
 NTCALL(SERVICE_ID_NtSetSystemInformation) = dx->OrigFuncNtSetSystemInformation;
 NTCALL(SERVICE_ID_NtCreatePort) = dx->OrigFuncNtCreatePort;
 NTCALL(SERVICE_ID_NtCreateFile) = dx->OrigFuncNtCreateFile;
 NTCALL(SERVICE_ID_NtQueryValueKey) = dx->OrigFuncNtQueryValueKey;
 NTCALL(SERVICE_ID_NtSetValueKey) = dx->OrigFuncNtSetValueKey;
 NTCALL(SERVICE_ID_NtRequestWaitReplyPort) = dx->OrigFuncNtRequestWaitReplyPort;
 NTCALL(SERVICE_ID_NtSecureConnectPort) = dx->OrigFuncNtSecureConnectPort;
 NTCALL(SERVICE_ID_NtOpenDirectoryObject) = dx->OrigFuncNtOpenDirectoryObject;

 __asm
  {
  mov eax, CR0Reg
  mov cr0, eax            // востановить содержимое CR0
  sti;
  }

 }

//----------------------------------------------------------------------------------------------------
// Функция поиска подмассива
//----------------------------------------------------------------------------------------------------
int __stdcall arrarr(BYTE *m1, ULONG s1, BYTE *m2, ULONG s2)
 {
 ULONG i, j;
 int pos = -1;
 for (i = 0; i < s1; i++)
  {
  if (m1[i] == m2[0])
   {
   BOOLEAN isfind = TRUE;
   for (j = 1; (j < s2) && (i + j < s1); j++)
    {
    isfind &= m1[i + j] == m2[j];
    if (!isfind) break;
    }
   if (isfind)
    {
    pos = i;
    break;
    }
   }
  }
 return pos;
 }

//----------------------------------------------------------------------------------------------------
// Функция определяющая, запущена ли сессия этой программой
//----------------------------------------------------------------------------------------------------
ULONG IsProgSession(ULONG SessionId)
 {
 PDEVICE_OBJECT fdo;
 ULONG i;

 if (SessionId == 0)
  return TRUE;

 SearchDevice(&fdo, MAIN_DEVICE);
 if (fdo)
  {
  PDRIVER_DEVICE_EXTENSION dx = (PDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
  for (i = 0; i < dx->LastWorkstation + 1; i ++)
   {
   if (dx->Sessions[i] == SessionId)
    return TRUE;
   }
  return FALSE;
  }
 else
  return FALSE;
 }

//----------------------------------------------------------------------------------------------------
// Функция для добавления к коду ошибки дополнительных параметров
//----------------------------------------------------------------------------------------------------
NTSTATUS ParseError(NTSTATUS my_error, NTSTATUS system_error)
 {
 #if DBG
  DbgPrint("M: OldErrorMsg %X\n", system_error);
 #endif
 system_error |= 0x20000000; //устанавливаем флаг пользовательской ошибки
 system_error |= my_error; //добавляем свои биты, указывающие на место где была ошибка
 return system_error;
 }

//----------------------------------------------------------------------------------------------------
// Функция поиска драйвера по имени
//----------------------------------------------------------------------------------------------------
PVOID SearchObject(PUNICODE_STRING pUni)
 {
 NTSTATUS st;
 HANDLE Handle;
 UNICODE_STRING Uni;
 OBJECT_ATTRIBUTES ObjectAttributes;
 PVOID Object;

 InitializeObjectAttributes(&ObjectAttributes, pUni, OBJ_CASE_INSENSITIVE, NULL, NULL);
 st = ObOpenObjectByName(&ObjectAttributes, 0L, 0L, 0L, 0L, 0L, &Handle);
 if (st != STATUS_SUCCESS)
  {
  DbgPrint("ObOpenObjectByName - ObOpenObjectByName failed %X\n", st);
  return (PVOID)0;
  }

 st = ObReferenceObjectByHandle(Handle, 0x80000000, NULL, 0, &Object, NULL);//Handle object
 if (st != STATUS_SUCCESS)
  {
  DbgPrint(( "ObReferenceObjectByHandle - ObReferenceObjectByHandle failed \n"));
  ZwClose(Handle);
  return (PVOID)0;
  }

 ZwClose(Handle);
 ObDereferenceObject(Object);

 return Object;
 }

//----------------------------------------------------------------------------------------------------
// Функция, определяющая серийные номера дисков
//----------------------------------------------------------------------------------------------------
BOOLEAN __stdcall GetBiosVersion(ULONG * BiosVers)
 {
 ULONG i;
 NTSTATUS status = STATUS_SUCCESS;
 UNICODE_STRING uKeyName;
 OBJECT_ATTRIBUTES KeyAttributes;
 HANDLE KeyHandle;
 MY_KEY_VALUE_PARTIAL_INFORMATION KeyInformation;
 ULONG DW;
 WCHAR Buffer[32];

 BiosVers[0] = 0x00;
 BiosVers[1] = 0x01;

 RtlInitUnicodeString(&uKeyName, L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\");
 InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
 status = ZwOpenKey(&KeyHandle, GENERIC_READ, &KeyAttributes);
 #if DBG
  DbgPrint("M: ZwOpenKey %X\n", status);
 #endif

 if (status == STATUS_SUCCESS)
  {
  UNICODE_STRING uSystemBiosVersion;
  swprintf(Buffer, L"%ws", L"SystemBiosDate");
  Buffer[10] = 0;
  swprintf(Buffer, L"%ws%s", Buffer, L"Version");

  RtlInitUnicodeString(&uSystemBiosVersion, Buffer);
  RtlZeroMemory(KeyInformation.Data, 1024);

  status = ZwQueryValueKey(KeyHandle, &uSystemBiosVersion, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   {
   for (i = 0; i < KeyInformation.DataLength / 2; i++)
    BiosVers[0] += KeyInformation.Data[i] * ((i % 3) ? 0x10000 : 0x1);

   for (i = KeyInformation.DataLength / 2; i < KeyInformation.DataLength; i++)
    BiosVers[1] += KeyInformation.Data[i] * ((i % 3) ? 0x10000 : 0x1);
   }

  ZwClose(KeyHandle);
  }


 return TRUE;
 }

//----------------------------------------------------------------------------------------------------
// Функция, определяющая CPUID
//----------------------------------------------------------------------------------------------------
BOOLEAN __stdcall GetCPUID(ULONG * CPUIDs)
 {
 ULONG upper = 0;
 ULONG middle = 0;
 ULONG lower = 0;

 __asm
  {
  jmp next

  _emit 0x01
  _emit 0x02
  _emit 0x04
  _emit 0x12
  _emit 0xA2
  _emit 0xA2
  _emit 0x12
  _emit 0x87

  next:

  mov eax, 0
  cpuid

  cmp eax, 3
  jl done

  mov eax, 0x01
  cpuid
  mov upper, eax
  mov middle, edx
  mov lower, ecx

  done:
  }

 CPUIDs[0] = upper;
 CPUIDs[1] = middle;
 CPUIDs[2] = lower;

 if (upper == 0 && middle == 0 && lower == 0)
  return FALSE; // failed
 else
  return TRUE; // success
}

//----------------------------------------------------------------------------------------------------
// Функция, формирующая AES ключ из HardwareID
//----------------------------------------------------------------------------------------------------
NTSTATUS GetAESKey(BYTE * buf)
 {
 NTSTATUS status = STATUS_SUCCESS;
 ULONG i;
 ULONG CPUIDs[3];
 ULONG BiosVers[3];
 ULONG * buf32;

 for (i = 0; i < AES_KEY_SIZE; i ++)
  buf[i] = (BYTE)i;

 GetCPUID(CPUIDs);

 #if DBG
 // DbgPrint("M: CPUIDs[0] %X\n", CPUIDs[0]);
 // DbgPrint("M: CPUIDs[1] %X\n", CPUIDs[1]);
 // DbgPrint("M: CPUIDs[2] %X\n", CPUIDs[2]);
 #endif

 CPUIDs[0] ^= 0x23F612C6;
 CPUIDs[1] ^= 0x9A61F54A;
 CPUIDs[2] ^= 0xF18C395D;

 GetBiosVersion(BiosVers);

 #if DBG
 // DbgPrint("M: BiosVers[0] %X\n", BiosVers[0]);
 // DbgPrint("M: BiosVers[1] %X\n", BiosVers[1]);
 #endif

 BiosVers[0] ^= 0x376CDA63;
 BiosVers[1] ^= 0x78F12DC5;

 buf32 = (ULONG *)buf;
 buf32[0] = 0x23456789;
 buf32[1] = CPUIDs[0];
 buf32[2] = CPUIDs[1];
 buf32[3] = CPUIDs[2];
 buf32[4] = 0x9ABCDEF1;
 buf32[5] = BiosVers[0];
 buf32[6] = BiosVers[1];
 buf32[7] = 0x23456789;

 #if DBG
  DbgPrint("M: 0 %X\n", buf32[0]);
  DbgPrint("M: 1 %X\n", buf32[1]);
  DbgPrint("M: 2 %X\n", buf32[2]);
  DbgPrint("M: 3 %X\n", buf32[3]);
  DbgPrint("M: 4 %X\n", buf32[4]);
  DbgPrint("M: 5 %X\n", buf32[5]);
  DbgPrint("M: 6 %X\n", buf32[6]);
  DbgPrint("M: 7 %X\n", buf32[7]);
 #endif

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция, возвращающая информацию о HID-устройствах
//----------------------------------------------------------------------------------------------------
NTSTATUS GetHIDDeviceInfo(PHID_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx)
 {
 NTSTATUS status = STATUS_SUCCESS;
 NTSTATUS status2;
 OBJECT_ATTRIBUTES ObjectAttributes;
 UNICODE_STRING ImhidDriverName;
 HANDLE hImhidDriver = NULL;
 PDRIVER_OBJECT pImhidDriver;
 PDEVICE_OBJECT pCurDevice;
 ULONG DW;
 WCHAR Buffer[64];

 RtlZeroMemory(DevicesInfo, sizeof(PHID_DEVICES_INFO));

 RtlInitUnicodeString(&ImhidDriverName, L"\\Driver\\imhidusb");
 InitializeObjectAttributes(&ObjectAttributes, &ImhidDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);

 status2 = ObOpenObjectByName(&ObjectAttributes, NULL, 0, 0, GENERIC_READ, NULL, &hImhidDriver);
 #if DBG
  DbgPrint("M: ObOpenObjectByName %X\n", status2);
 #endif
 if (status2 == STATUS_SUCCESS) //этого драйвера может и не быть вовсе
  {
  status2 = ObReferenceObjectByHandle(hImhidDriver, FILE_ANY_ACCESS, NULL, KernelMode,(PVOID *)&pImhidDriver, NULL);
  #if DBG
   DbgPrint("M: ObReferenceObjectByHandle %X\n", status2);
  #endif
  if (status2 == STATUS_SUCCESS)
   {
   pCurDevice = pImhidDriver->DeviceObject;
   while (pCurDevice)
    {
    #if DBG
     DbgPrint("M: pCurDevice %X\n", pCurDevice);
    #endif

    RtlZeroMemory(Buffer, sizeof(Buffer));
    status2 = IoGetDeviceProperty(pCurDevice, DevicePropertyDriverKeyName, sizeof(Buffer), Buffer, &DW);
    #if DBG
     DbgPrint("M: DevicePropertyDriverKeyName %ws\n", Buffer);
    #endif

    if (wcslen(Buffer) && (DevicesInfo->iDeviceCount < 10)) //не бум всякие левые устройства добавлять в список и следим что бы не более 10 устройств
     {
     wcsncpy(DevicesInfo->HidDevices[DevicesInfo->iDeviceCount].HidKeyName, Buffer, 64);

     RtlZeroMemory(Buffer, sizeof(Buffer));
     status2 = IoGetDeviceProperty(pCurDevice, DevicePropertyDeviceDescription, sizeof(Buffer), Buffer, &DW);
     #if DBG
      DbgPrint("M: DevicePropertyDeviceDescription %ws\n", Buffer);
     #endif
     wcsncpy(DevicesInfo->HidDevices[DevicesInfo->iDeviceCount].HidDescription, Buffer, 64);

     DevicesInfo->iDeviceCount ++;
     }

    pCurDevice = pCurDevice->NextDevice;
    }

   ObDereferenceObject(pImhidDriver);
   }
  ZwClose(hImhidDriver);
  }

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция, возвращающая информацию о видеоустройствах
//----------------------------------------------------------------------------------------------------
NTSTATUS GetVideoDeviceInfo(PVIDEO_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG i;
 NTSTATUS status = STATUS_SUCCESS;
 NTSTATUS status2;
 WCHAR Buffer[32];
 WCHAR wcVgaCompatibleDevName[32];
 ULONG iVideoDeviceCount;
 BOOLEAN IsMirror;
 MY_KEY_VALUE_PARTIAL_INFORMATION KeyInformation;
 ULONG DW;
 UNICODE_STRING uKeyName;
 OBJECT_ATTRIBUTES KeyAttributes;
 HANDLE KeyHandle;

 RtlZeroMemory(DevicesInfo, sizeof(VIDEO_DEVICES_INFO));
 RtlInitUnicodeString(&uKeyName, L"\\REGISTRY\\MACHINE\\HARDWARE\\DEVICEMAP\\VIDEO\\");
 InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
 status = ZwOpenKey(&KeyHandle, GENERIC_READ, &KeyAttributes);
 #if DBG
  DbgPrint("M: ZwOpenKey %X\n", status);
 #endif

 if (status == STATUS_SUCCESS)
  {
  UNICODE_STRING uMaxObjectNumber;
  UNICODE_STRING uVgaCompatible;
  RtlInitUnicodeString(&uMaxObjectNumber, L"MaxObjectNumber");
  RtlZeroMemory(KeyInformation.Data, 1024);
  status2 = ZwQueryValueKey(KeyHandle, &uMaxObjectNumber, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status2 == STATUS_SUCCESS)
   {
   #if DBG
    DbgPrint("M: MaxObjectNumber %X\n", *((ULONG*)KeyInformation.Data));
   #endif
   iVideoDeviceCount = *((int*)KeyInformation.Data);
   }
  else
   iVideoDeviceCount = 10;

  iVideoDeviceCount = (iVideoDeviceCount > 10) ? 10 : iVideoDeviceCount;

  RtlInitUnicodeString(&uVgaCompatible, L"VgaCompatible");
  RtlZeroMemory(KeyInformation.Data, 1024);
  status2 = ZwQueryValueKey(KeyHandle, &uVgaCompatible, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status2 == STATUS_SUCCESS)
   wcsncpy(wcVgaCompatibleDevName, (PWCHAR)KeyInformation.Data, 32);
  else
   RtlZeroMemory(wcVgaCompatibleDevName, 32);

  #if DBG
   DbgPrint("M: uVgaCompatible %ws\n", wcVgaCompatibleDevName);
  #endif

  for (i = 0; i < iVideoDeviceCount + 1; i++)
   {
   WCHAR wcValueName[32];
   IsMirror = FALSE;

   RtlZeroMemory(wcValueName, 32);
   swprintf(wcValueName, L"\\Device\\Video%d", i);

   if (wcsncmp(wcVgaCompatibleDevName, wcValueName, 32) != 0)
    {
    PDEVICE_OBJECT pCurDevice = NULL;
    swprintf(Buffer, L"Video%d", i);
    SearchDevice(&pCurDevice, Buffer);
    if (pCurDevice)
     {
     PPDO_LIST pPdoList;
     IO_STATUS_BLOCK  IoStatusBlock;
     PIRP MyIrp = IoBuildDeviceIoControlRequest(0x230018, pCurDevice, NULL, 0, &pPdoList, 4, 0, NULL, &IoStatusBlock);
     PDEVICE_OBJECT pPdoDevice;
     UNICODE_STRING uValueName;
     DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].VideoNumber = i;
     #if DBG
      DbgPrint("M: MyIrp %X\n", MyIrp);
     #endif

     if (MyIrp)
      {
      WCHAR wcDeviceDescription[64];
      status2 = IofCallDriver(pCurDevice, MyIrp);
      pPdoDevice = NULL;
      if (status2 == STATUS_SUCCESS)
       {
       ULONG j = 0;
       while (pPdoList[j].Flag)
        {
        if (pPdoList[j].Flag & 0x00000001)
         {
         #if DBG
          DbgPrint("M: Flag %X\n", pPdoList[j].Flag);
          DbgPrint("M: DeviceObject %X\n", pPdoList[j].DeviceObject);
         #endif
         pPdoDevice = pPdoList[j].DeviceObject;
         ObReferenceObject(pPdoDevice);
         break;
         }
        j ++;
        }
       }

      if (pPdoDevice)
       {
       status2 = IoGetDeviceProperty(pPdoDevice, DevicePropertyDeviceDescription, 1024, wcDeviceDescription, &DW);
       if (status2 == STATUS_SUCCESS)
        {
        #if DBG
         DbgPrint("M: IoGetDeviceProperty %X\n", status2);
         //DbgPrint("M: wcDeviceDescription %ls\n", wcDeviceDescription);
        #endif
        wcsncpy(DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].MonitorDescription, wcDeviceDescription, 64);
        }
       ObDereferenceObject(pPdoDevice);
       }
      }
     else
      {
      #if DBG
       DbgPrint("M: Error call IofCallDriver=%X Device=%X\n", status, pCurDevice);
      #endif
      status = ParseError(STATUS_VIDEOINFO_CALL_DRIVER, status);
      }

     RtlInitUnicodeString(&uValueName, wcValueName);
     RtlZeroMemory(KeyInformation.Data, 1024);
     status2 = ZwQueryValueKey(KeyHandle, &uValueName, KeyValuePartialInformation, &KeyInformation,
      1024, &DW);
     if (status2 == STATUS_SUCCESS)
      {
      UNICODE_STRING uServKeyName;
      OBJECT_ATTRIBUTES ServKeyAttributes;
      HANDLE ServKeyHandle;
      #if DBG
       DbgPrint("M: ServiceKey %ws\n", KeyInformation.Data);
      #endif
      RtlInitUnicodeString(&uServKeyName, (PCWSTR)KeyInformation.Data);
      InitializeObjectAttributes(&ServKeyAttributes, &uServKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
      status2 = ZwOpenKey(&ServKeyHandle, GENERIC_READ, &ServKeyAttributes);
      #if DBG
       DbgPrint("M: ZwOpenKey %X\n", status2);
      #endif
      if (status2 == STATUS_SUCCESS)
       {
       UNICODE_STRING uDescValueName;
       UNICODE_STRING uMirrorDriver;

       //Переменные для проверки кол-ва запусков
       ULONG TmpValue;
       ULONG TmpFk = 4;
       //
       RtlInitUnicodeString(&uDescValueName, L"Device Description");
       RtlInitUnicodeString(&uMirrorDriver, L"MirrorDriver");

       RtlZeroMemory(KeyInformation.Data, 1024);
       status2 = ZwQueryValueKey(ServKeyHandle, &uDescValueName, KeyValuePartialInformation, &KeyInformation,
        1024, &DW);
       if (status2 == STATUS_SUCCESS)
        {
        #if DBG
         DbgPrint("M: DescValue %ws\n", KeyInformation.Data);
        #endif
        wcsncpy(DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].VideoDescription,
         (PCWSTR)KeyInformation.Data, 64);
        }
       else
        {
        #if DBG
         DbgPrint("M: Error call Device Description ZwOpenKey=%X VIDEO%d\n", status, i);
        #endif
        RtlZeroMemory(DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].VideoDescription, 128);
        }

       //Получение из реестра количества запусков (да, я извращенец)
       RtlInitUnicodeString(&uDescValueName, DEMO_REG_STARTUP_COUNT);
       RtlZeroMemory(KeyInformation.Data, 1024);
       status2 = ZwQueryValueKey(ServKeyHandle, &uDescValueName, KeyValuePartialInformation, &KeyInformation,
        1024, &DW);

       if (status2 == STATUS_SUCCESS)
        {
        TmpValue = *((ULONG *)KeyInformation.Data);
        #if DBG
         DbgPrint("M: Device Attach %X\n", TmpValue);
        #endif
        }
       else
        {
        TmpValue = 0;
        #if DBG
         DbgPrint("M: Error call Device Attach ZwOpenKey=%X VIDEO%d\n", status2, i);
        #endif
        }

       TmpValue += TmpFk / 4;
       if (TmpValue < MAX_DEMO_STARTUP)
        {
        #if DEMO
         dx->CanDemoStartSession2 = 0x1; //можно
        #else
         dx->CanDemoStartSession3 = 0x1; //нифига не делает, а CanDemoStartSession2 устанавливаем в секретном учаске кода
        #endif
        }
       else
        if (TmpValue > 1024) //фейковая проверка
         dx->CanDemoStartSession2 = 0x4; //ХЗ
        else
       //конец

       RtlZeroMemory(KeyInformation.Data, 1024);
       status2 = ZwQueryValueKey(ServKeyHandle, &uMirrorDriver, KeyValuePartialInformation, &KeyInformation,
        1024, &DW);

       if (status2 == STATUS_SUCCESS)
        {
        #if DBG
         DbgPrint("M: uMirrorDriver %X\n", *((ULONG*)KeyInformation.Data));
        #endif
        IsMirror = (BOOLEAN) *((ULONG*)KeyInformation.Data);
        }
       else
        {
        IsMirror = FALSE;
        }

       //ещё кусочек бреда
       if (dx->LastWorkstation == 0x1)
        {
        status2 = ZwSetValueKey(ServKeyHandle, &uDescValueName, 0, REG_DWORD, &TmpValue, TmpFk);
        #if DBG
         DbgPrint("M: ZwSetValueKey Device Attach ZwSetValueKey=%X VIDEO%d\n", status2, i);
        #endif
        }

       if (TmpValue >= MAX_DEMO_STARTUP)
        dx->LastWorkstation = TmpValue * 256;

       //конец

       ZwClose(ServKeyHandle);
       }
      else
       {
       #if DBG
        DbgPrint("M: Error call ZwOpenKey=%X VIDEO%d\n", status, i);
       #endif
       }
      }
     else
      {
      #if DBG
       DbgPrint("M: Error call ZwQueryValueKey=%X VIDEO%d\n", status, i);
      #endif
      }

     if (!IsMirror)
      {
      #if DBG
       DbgPrint("M: DeviceInfo %d %ws %ws \n", DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].VideoNumber,
        DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].VideoDescription,
        DevicesInfo->VideoDevices[DevicesInfo->iDeviceCount].MonitorDescription);
      #endif

      DevicesInfo->iDeviceCount ++;
      }
     }
    }
   }
  ZwClose(KeyHandle);
  }
 else
  {
  #if DBG
   DbgPrint("=KBD= Error call VIDEO ZwOpenKey\n", status);
  #endif
  status = ParseError(STATUS_OPEN_VIDEO_KEY, status);
  }

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция, возвращающая информацию о устройствах ввода
//----------------------------------------------------------------------------------------------------
NTSTATUS GetInputDeviceInfo(PINPUT_DEVICES_INFO DevicesInfo, PDRIVER_DEVICE_EXTENSION dx, INPUT_DEVICE_TYPE InputType)
 {
 NTSTATUS status = STATUS_SUCCESS;
 NTSTATUS status2;
 WCHAR Buffer[32];
 ULONG iInputDeviceCount = 0;
 MY_KEY_VALUE_PARTIAL_INFORMATION KeyInformation;
 ULONG DW;
 WCHAR wcDeviceBaseName[32];
 UNICODE_STRING uKeyName;
 OBJECT_ATTRIBUTES KeyAttributes;
 HANDLE KeyHandle;
 ULONG i;

 RtlZeroMemory(DevicesInfo, sizeof(INPUT_DEVICES_INFO));
 if (InputType == Keyboard)
  RtlInitUnicodeString(&uKeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Kbdclass\\Parameters\\");
 else
  RtlInitUnicodeString(&uKeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Mouclass\\Parameters\\");

 InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

 status2 = ZwOpenKey(&KeyHandle, GENERIC_READ, &KeyAttributes);
 #if DBG
  DbgPrint("M: ZwOpenKey %X\n", status);
 #endif

 if (status2 == STATUS_SUCCESS)
  {
  UNICODE_STRING uParamDeviceBaseName;
  if (InputType == Keyboard)
   RtlInitUnicodeString(&uParamDeviceBaseName, L"KeyboardDeviceBaseName");
  else
   RtlInitUnicodeString(&uParamDeviceBaseName, L"PointerDeviceBaseName");

  RtlZeroMemory(KeyInformation.Data, 1024);
  status2 = ZwQueryValueKey(KeyHandle, &uParamDeviceBaseName, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status2 == STATUS_SUCCESS)
   wcsncpy(wcDeviceBaseName, (PWCHAR)KeyInformation.Data, 32);
  else
   {
   DbgPrint("M: Error call DeviceBaseName ZwQueryValueKey=%X\n", status);
   if (InputType == Keyboard)
    wcscpy(wcDeviceBaseName, L"KeyboardClass");
   else
    wcscpy(wcDeviceBaseName, L"PointerClass");
   }
  ZwClose(KeyHandle);
  }
 else
  {
  if (InputType == Keyboard)
   wcscpy(wcDeviceBaseName, L"KeyboardClass");
  else
   wcscpy(wcDeviceBaseName, L"PointerClass");
  }
 #if DBG
  DbgPrint("M: wcDeviceBaseName %ws\n", wcDeviceBaseName);
 #endif

 DevicesInfo->iDeviceCount = 0;
 for (i = 0; i < 10; i++)
  {
  PDEVICE_OBJECT pCurDevice = NULL;
  swprintf(Buffer, L"%ws%d", wcDeviceBaseName, i);
  SearchDevice(&pCurDevice, Buffer);
  #if DBG
   DbgPrint("M: Buffer %ws\n", Buffer);
  #endif
  if (pCurDevice)
   {
   PDEVICE_OBJECT InputDevice = IoGetDeviceAttachmentBaseRef(pCurDevice);
   WCHAR wcDeviceDescription[1024];
   BOOLEAN IsRDP = FALSE;
   #if DBG
    DbgPrint("M: InputDevice %X\n", InputDevice);
   #endif
   status2 = IoGetDeviceProperty(InputDevice, DevicePropertyHardwareID, 1024, wcDeviceDescription, &DW);
   #if DBG
    DbgPrint("M: IoGetDeviceProperty %X\n", status);
   #endif
   if (status2 == STATUS_SUCCESS)
    {
    #if DBG
     DbgPrint("M: DevicePropertyHardwareID %ws\n", wcDeviceDescription);
    #endif
    IsRDP = (wcsstr(wcDeviceDescription, L"RDP_MOU") || wcsstr(wcDeviceDescription, L"RDP_KBD"));
    }

   if (! IsRDP)
    {
    status2 = IoGetDeviceProperty(InputDevice, DevicePropertyDeviceDescription, 1024, wcDeviceDescription, &DW);
    #if DBG
     DbgPrint("M: IoGetDeviceProperty %X\n", status);
    #endif
    if (status2 == STATUS_SUCCESS)
     {
     DevicesInfo->InputDevices[DevicesInfo->iDeviceCount].InputNumber = i;
     wcsncpy(DevicesInfo->InputDevices[DevicesInfo->iDeviceCount].InputDescription, wcDeviceDescription, 256);
     DevicesInfo->InputDevices[DevicesInfo->iDeviceCount].InputType = InputType;
     #if DBG
      DbgPrint("M: wcDeviceDescription %ws\n", wcDeviceDescription);
     #endif
     DevicesInfo->iDeviceCount ++;
     }

    }
   }
  }

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция получения настроек
//----------------------------------------------------------------------------------------------------
NTSTATUS GetSettings(PSETTINGS Settings, PDRIVER_DEVICE_EXTENSION dx)
 {
 NTSTATUS status = STATUS_SUCCESS;
 WCHAR Buffer[32];
 MY_KEY_VALUE_PARTIAL_INFORMATION KeyInformation;
 ULONG DW;
 ULONG i;
 UNICODE_STRING uKeyName;
 OBJECT_ATTRIBUTES KeyAttributes;
 HANDLE KeyHandle;
 UNICODE_STRING uHidKeyName;
 OBJECT_ATTRIBUTES HidKeyAttributes;
 HANDLE HidKeyHandle;

 RtlZeroMemory(Settings, sizeof(SETTINGS));
 RtlInitUnicodeString(&uKeyName, PROG_PATH);
 InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
 status = ZwOpenKey(&KeyHandle, GENERIC_READ, &KeyAttributes);
 #if DBG
  DbgPrint("M: ZwOpenKey %X\n", status);
 #endif
 if (status == STATUS_SUCCESS)
  {
  UNICODE_STRING uParameter;

  //Получим список процессов, которым нужновсегда возвращать 0 сессию
  RtlInitUnicodeString(&uParameter, L"NullSessionProcList");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);

  if (status == STATUS_SUCCESS)
   {
   ULONG n;
   RtlZeroMemory(dx->NullSessionProcList, 1024);
   for (n = 0; n < 1024 / 2; n ++)
    dx->NullSessionProcList[n] = KeyInformation.Data[n * 2];
   }
  else
   RtlZeroMemory(dx->NullSessionProcList, 1024);

  //Узнаем, можно ли разрешать быстрое переключение пользователей
  RtlInitUnicodeString(&uParameter, L"EnableMultipleTSSessions");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);

  if (status == STATUS_SUCCESS)
   dx->EnableMultipleTSSessions = *((ULONG *)KeyInformation.Data);
  else
   dx->EnableMultipleTSSessions = 0;

  //Узнаем, нужно ли проверять наличие всех устройств для основоного места
  RtlInitUnicodeString(&uParameter, L"DisableHostDeviceCheck");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);

  if (status == STATUS_SUCCESS)
   dx->DisableHostDeviceCheck = *((ULONG *)KeyInformation.Data);
  else
   dx->DisableHostDeviceCheck = 0;

  RtlInitUnicodeString(&uParameter, L"WorkstationsCount");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   Settings->WorkstationsCount = *((ULONG *)KeyInformation.Data);
  else
   Settings->WorkstationsCount = 2;

  RtlInitUnicodeString(&uParameter, L"EnableIP");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   Settings->EnableIP = *((ULONG *)KeyInformation.Data);
  else
   Settings->EnableIP = 0;

  //Использовать ли привязку к ядрам
  RtlInitUnicodeString(&uParameter, L"EnableCPU");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   Settings->EnableCPU = *((ULONG *)KeyInformation.Data);
  else
   Settings->EnableCPU = 0;

  //Использовать ли привязку для всех процессов, а не только потомков winlogon.exe
  RtlInitUnicodeString(&uParameter, L"EnableCPUForAll");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   Settings->EnableCPUForAll = *((ULONG *)KeyInformation.Data);
  else
   Settings->EnableCPUForAll = 0;

  memset(Settings->Data, 0x90, SECR_CODE_SIZE);
  RtlInitUnicodeString(&uParameter, L"Data");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   RtlCopyMemory(Settings->Data, KeyInformation.Data, SECR_CODE_SIZE);

  RtlInitUnicodeString(&uParameter, L"GlobTerminalVar");
  status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
   1024, &DW);
  if (status == STATUS_SUCCESS)
   Settings->GlobTerminalVar = *((ULONG *)KeyInformation.Data);
  else
   Settings->GlobTerminalVar = 0xFFFFFFFF;

  //в демо-версии запретим использование автозапуска
  #if DEMO

  #else
   RtlInitUnicodeString(&uParameter, L"AutoStart");
   status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
    1024, &DW);
   if (status == STATUS_SUCCESS)
    Settings->AutoStart = *((ULONG *)KeyInformation.Data);
   else
    Settings->AutoStart = 0;
  #endif

  for (i = 0; i < 10; i++)
   {
   swprintf(Buffer, L"Video%d", i);
   RtlInitUnicodeString(&uParameter, Buffer);
   status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
    1024, &DW);
   if (status == STATUS_SUCCESS)
    Settings->Video[i] = *((ULONG *)KeyInformation.Data);
   else
    Settings->Video[i] = 0;

   swprintf(Buffer, L"Keyboards%d", i);
   RtlInitUnicodeString(&uParameter, Buffer);
   status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
    1024, &DW);
   if (status == STATUS_SUCCESS)
    Settings->Keyboards[i] = *((ULONG *)KeyInformation.Data);
   else
    Settings->Keyboards[i] = 0;

   swprintf(Buffer, L"Pointers%d", i);
   RtlInitUnicodeString(&uParameter, Buffer);
   status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
    1024, &DW);
   if (status == STATUS_SUCCESS)
    Settings->Pointers[i] = *((ULONG *)KeyInformation.Data);
   else
    Settings->Pointers[i] = 0;

   swprintf(Buffer, L"IPs%d", i);
   RtlInitUnicodeString(&uParameter, Buffer);
   status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
    1024, &DW);
   if (status == STATUS_SUCCESS)
    Settings->IPs[i] = *((ULONG *)KeyInformation.Data);
   else
    Settings->IPs[i] = 0;

   swprintf(Buffer, L"CPUMask%d", i);
   RtlInitUnicodeString(&uParameter, Buffer);
   status = ZwQueryValueKey(KeyHandle, &uParameter, KeyValuePartialInformation, &KeyInformation,
    1024, &DW);
   if (status == STATUS_SUCCESS)
    Settings->CPUMask[i] = *((ULONG *)KeyInformation.Data);
   else
    Settings->CPUMask[i] = 0;
   }

  //получим настройки HID устройств
  RtlInitUnicodeString(&uHidKeyName, PROG_PATH L"HIDDevices\\");
  InitializeObjectAttributes(&HidKeyAttributes, &uHidKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
  ZwOpenKey(&HidKeyHandle, GENERIC_READ, &HidKeyAttributes);
  if (status == STATUS_SUCCESS)
   {
   RtlZeroMemory(&KeyInformation, 1024);
   i = 0;
   //переберём все HID устройства
   while (ZwEnumerateValueKey(HidKeyHandle, i, KeyValueBasicInformation, &KeyInformation,
    1024, &DW) == STATUS_SUCCESS)
    {
    wcsncpy(Settings->Hids[i].HidKeyName, (PWCHAR)KeyInformation.Data, 64);

    RtlZeroMemory(&KeyInformation, 1024);
    status = ZwEnumerateValueKey(HidKeyHandle, i, KeyValuePartialInformation, &KeyInformation,
     1024, &DW);

    Settings->Hids[i].Mask = *((ULONG *)KeyInformation.Data);

    RtlZeroMemory(&KeyInformation, 1024);
    i ++;
    }

   ZwClose(HidKeyHandle);
   }
  else
   {
   #if DBG
    DbgPrint("M: Cant open HID ZwCreateKey %X\n", status);
   #endif
   }

  status = STATUS_SUCCESS;
  }
 else
  {
  #if DBG
   DbgPrint("M: ZwOpenKey %X\n", status);
  #endif
  Settings->WorkstationsCount = 2;
  for (i = 0; i < 10; i++)
   {
   Settings->Video[i] = 0;
   Settings->Keyboards[i] = 0;
   Settings->Pointers[i] = 0;
   }
  status = STATUS_SUCCESS;
  }

 return STATUS_SUCCESS;
 }

//----------------------------------------------------------------------------------------------------
// Функция получения стартовых настроек
//----------------------------------------------------------------------------------------------------
NTSTATUS GetStartSettings(PSETTINGS Settings, PDRIVER_DEVICE_EXTENSION dx)
 {
 if (dx->StartOnBoot)
  {
  RtlCopyMemory(Settings, dx->StartSettings, sizeof(SETTINGS));
  return STATUS_SUCCESS;
  }
 else
  return GetSettings(Settings, dx);
 }

//----------------------------------------------------------------------------------------------------
// Функция находит PDO для каждого HID устройства в настройках
//----------------------------------------------------------------------------------------------------
NTSTATUS UpdateHidsPDO(PDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG i;
 NTSTATUS status2;
 OBJECT_ATTRIBUTES ObjectAttributes;
 UNICODE_STRING ImhidDriverName;
 HANDLE hImhidDriver = NULL;
 PDRIVER_OBJECT pImhidDriver;
 PDEVICE_OBJECT pCurDevice;
 ULONG DW;
 WCHAR Buffer[64];

 for (i = 0; i < 10; i++)
  dx->HidsPDO[i] = NULL;

 //находим HID устройства в системе

 RtlInitUnicodeString(&ImhidDriverName, L"\\Driver\\imhidusb");
 InitializeObjectAttributes(&ObjectAttributes, &ImhidDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);

 status2 = ObOpenObjectByName(&ObjectAttributes, NULL, 0, 0, GENERIC_READ, NULL, &hImhidDriver);
 #if DBG
  DbgPrint("M: ObOpenObjectByName %X\n", status2);
 #endif
 if (status2 == STATUS_SUCCESS) //этого драйвера может и не быть вовсе
  {
  status2 = ObReferenceObjectByHandle(hImhidDriver, FILE_ANY_ACCESS, NULL, KernelMode,(PVOID *)&pImhidDriver, NULL);
  #if DBG
   DbgPrint("M: ObReferenceObjectByHandle %X\n", status2);
  #endif
  if (status2 == STATUS_SUCCESS)
   {
   pCurDevice = pImhidDriver->DeviceObject;
   while (pCurDevice)
    {
    #if DBG
     DbgPrint("M: pCurDevice %X\n", pCurDevice);
    #endif

    RtlZeroMemory(Buffer, sizeof(Buffer));
    status2 = IoGetDeviceProperty(pCurDevice, DevicePropertyDriverKeyName, sizeof(Buffer), Buffer, &DW);
    #if DBG
     DbgPrint("M: DevicePropertyDriverKeyName %ws\n", Buffer);
    #endif

    if (wcslen(Buffer)) //не бум всякие левые устройства проверять
     {
     //перебираем все HID устройства в списке настроек и ищем совпадения по куску реестра
     for (i = 0; i < 10; i++)
      if (!_wcsicmp(dx->StartSettings->Hids[i].HidKeyName, Buffer))
       dx->HidsPDO[i] = pCurDevice;
     }

    pCurDevice = pCurDevice->NextDevice;
    }

   ObDereferenceObject(pImhidDriver);
   }
  ZwClose(hImhidDriver);
  }

 return STATUS_SUCCESS;
 }

//----------------------------------------------------------------------------------------------------
// Функция обновления стартовых настроек при изменении настроек
//----------------------------------------------------------------------------------------------------
NTSTATUS UpdateStartSettings(PSETTINGS Settings, PDRIVER_DEVICE_EXTENSION dx)
 {
 if (dx->StartOnBoot) //если программа запущена не при загрузки, то не будем ничего обновлять и так StartSettings = Settings
  {
  //диначмически обновим настройки HID устройств
  RtlCopyMemory(dx->StartSettings->Hids, Settings->Hids, sizeof(HID_DEVICE_SETTING) * 10);
  UpdateHidsPDO(dx);
  //динамически обновим настройки CPU
  //пока не обновляем
  //RtlCopyMemory(dx->StartSettings.CPUMask, Settings->CPUMask, sizeof(ULONG) * 10);
  //dx->StartSettings.EnableCPU = Settings->EnableCPU;
  }
 return STATUS_SUCCESS;
 }

//----------------------------------------------------------------------------------------------------
// Функция сохранения настроек
//----------------------------------------------------------------------------------------------------
NTSTATUS SetSettings(PSETTINGS Settings, PDRIVER_DEVICE_EXTENSION dx)
 {
 NTSTATUS status = STATUS_SUCCESS;
 WCHAR Buffer[32];
 ULONG i;
 BOOLEAN HaveConsoleVideo = FALSE;
 BOOLEAN HaveConsoleKeyboard = FALSE;
 BOOLEAN HaveConsolePointer = FALSE;
 ULONG DW;

 PVIDEO_DEVICES_INFO VideoDevicesInfo = (PVIDEO_DEVICES_INFO)ExAllocatePoolWithTag(PagedPool, sizeof(VIDEO_DEVICES_INFO), TAG);
 GetVideoDeviceInfo(VideoDevicesInfo, dx);

 for (i = 0; i < VideoDevicesInfo->iDeviceCount; i ++)
  HaveConsoleVideo |= (Settings->Video[VideoDevicesInfo->VideoDevices[i].VideoNumber] == 1);

 ExFreePool(VideoDevicesInfo);

 if (HaveConsoleVideo)
  {
  PINPUT_DEVICES_INFO InputDevicesInfo = (PINPUT_DEVICES_INFO)ExAllocatePoolWithTag(PagedPool, sizeof(INPUT_DEVICES_INFO ), TAG);
  GetInputDeviceInfo(InputDevicesInfo, dx, Keyboard);

  for (i = 0; i < InputDevicesInfo->iDeviceCount; i ++)
   HaveConsoleKeyboard |= (Settings->Keyboards[InputDevicesInfo->InputDevices[i].InputNumber] == 1);

  ExFreePool(InputDevicesInfo);

  if (HaveConsoleKeyboard)
   {
   PINPUT_DEVICES_INFO InputDevicesInfo = (PINPUT_DEVICES_INFO)ExAllocatePoolWithTag(PagedPool, sizeof(INPUT_DEVICES_INFO ), TAG);
   GetInputDeviceInfo(InputDevicesInfo, dx, Pointer);

   for (i = 0; i < InputDevicesInfo->iDeviceCount; i ++)
    HaveConsolePointer |= (Settings->Pointers[InputDevicesInfo->InputDevices[i].InputNumber] == 1);

   ExFreePool(InputDevicesInfo);

   if (HaveConsolePointer)
    {
    UNICODE_STRING uKeyName;
    OBJECT_ATTRIBUTES KeyAttributes;
    HANDLE KeyHandle;

    RtlInitUnicodeString(&uKeyName, PROG_PATH);
    InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes, 0, NULL,
     REG_OPTION_NON_VOLATILE, &DW);
    #if DBG
     DbgPrint("M: ZwCreateKey %X\n", status);
    #endif
    if (status == STATUS_SUCCESS)
     {
     UNICODE_STRING uServKeyName;
     OBJECT_ATTRIBUTES ServKeyAttributes;
     HANDLE ServKeyHandle;

     UNICODE_STRING uHidKeyName;
     OBJECT_ATTRIBUTES HidKeyAttributes;
     HANDLE HidKeyHandle;

     UNICODE_STRING uParameter;
     RtlInitUnicodeString(&uParameter, L"WorkstationsCount");
     status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->WorkstationsCount, 4);

     RtlInitUnicodeString(&uParameter, L"EnableIP");
     status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->EnableIP, 4);

     RtlInitUnicodeString(&uParameter, L"AutoStart");
     status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->AutoStart, 4);

     RtlInitUnicodeString(&uParameter, L"EnableCPU");
     status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->EnableCPU, 4);

     RtlInitUnicodeString(&uParameter, L"EnableCPUForAll");
     status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->EnableCPUForAll, 4);

     RtlInitUnicodeString(&uServKeyName, AFDHOOK_PATH);
     InitializeObjectAttributes(&ServKeyAttributes, &uServKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
     status = ZwOpenKey(&ServKeyHandle, GENERIC_WRITE, &ServKeyAttributes);
     #if DBG
      DbgPrint("M: ZwOpenKey Tcphook %X\n", status);
     #endif

     if (status == STATUS_SUCCESS)
      {
      UNICODE_STRING uStartType;
      ULONG Value;
      RtlInitUnicodeString(&uStartType, L"Start");
      if (Settings->EnableIP)
       Value = 1;
      else
       Value = 3;
      status = ZwSetValueKey(ServKeyHandle, &uStartType, 0, REG_DWORD, &Value, 4);
      }

     for (i = 0; i < 10; i++)
      {
      swprintf(Buffer, L"Video%d", i);
      RtlInitUnicodeString(&uParameter, Buffer);
      status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->Video[i], 4);

      swprintf(Buffer, L"Keyboards%d", i);
      RtlInitUnicodeString(&uParameter, Buffer);
      status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->Keyboards[i], 4);

      swprintf(Buffer, L"Pointers%d", i);
      RtlInitUnicodeString(&uParameter, Buffer);
      status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->Pointers[i], 4);

      swprintf(Buffer, L"IPs%d", i);
      RtlInitUnicodeString(&uParameter, Buffer);
      status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->IPs[i], 4);

      swprintf(Buffer, L"CPUMask%d", i);
      RtlInitUnicodeString(&uParameter, Buffer);
      status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_DWORD, &Settings->CPUMask[i], 4);
      }

     //сохраним настройки HID устройств
     RtlInitUnicodeString(&uHidKeyName, PROG_PATH L"HIDDevices\\");
     InitializeObjectAttributes(&HidKeyAttributes, &uHidKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
     status = ZwCreateKey(&HidKeyHandle, KEY_ALL_ACCESS, &HidKeyAttributes, 0, NULL,
     REG_OPTION_NON_VOLATILE, &DW);
     if (status == STATUS_SUCCESS)
      {
      for (i = 0; i < 10; i++)
       {
       if (wcslen(Settings->Hids[i].HidKeyName))
        {
        RtlInitUnicodeString(&uParameter, Settings->Hids[i].HidKeyName);
        status = ZwSetValueKey(HidKeyHandle, &uParameter, 0, REG_DWORD, &Settings->Hids[i].Mask, 4);
        }
       }
      ZwClose(HidKeyHandle);
      }
     else
      {
      #if DBG
       DbgPrint("M: Cant open/create HID ZwCreateKey %X\n", status);
      #endif
      }
     //

     ZwClose(KeyHandle);
     }
    else
     {
     #if DBG
      DbgPrint("M: Cant open/create ZwCreateKey %X\n", status);
     #endif
     //status = ParseError();
     }

    //Проапгрейдим какие надо текущие настройки
    UpdateStartSettings(Settings, dx);
    }
   else
    {
    status = STATUS_NO_POINTER_FOR_CONCOLE;
    }
   }
  else
   {
   status = STATUS_NO_KEYBOARD_FOR_CONCOLE;
   }
  }
 else
  {
  status = STATUS_NO_VIDEO_FOR_CONCOLE;
  }

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция сохранения очень секретного кода
//----------------------------------------------------------------------------------------------------
NTSTATUS SetSecretCode(BYTE * SecretCode, PDRIVER_DEVICE_EXTENSION dx)
 {
 NTSTATUS status = STATUS_SUCCESS;
 WCHAR Buffer[32];

 ULONG DW;

 //расшифровка кода
 int Nr = 256;
 int Nk = Nr / 32;
 unsigned char RoundKey[240];
 unsigned char out[SECR_CODE_SIZE] = {0};
 unsigned char Key[32] = {0};
 ULONG * out32 = (ULONG *)out;
 ULONG filesize;
 ULONG src;
 ULONG i;

 Nr = Nk + 6;
 status = GetAESKey(Key);
 if (status == STATUS_SUCCESS)
  {
  KeyExpansion(Nk, Nr, RoundKey, Key, Rcon);
  for (i = 0; i < SECR_CODE_SIZE; i += 16)
   InvCipher(Nr, &SecretCode[i], &out[i], RoundKey);

  filesize = out32[SECR_CODE_SIZE / 4 - 1];

  src = 0;
  if (filesize < SECR_CODE_SIZE)
   {
   for (i = 0; i < filesize; i ++)
    src += (BYTE)out[i];
   }
  //конец расшифровки

  if (out32[SECR_CODE_SIZE / 4 - 3] == VERSION)
   {
   if ((filesize < SECR_CODE_SIZE) && (src == out32[SECR_CODE_SIZE / 4 - 2]))
    {
    UNICODE_STRING uKeyName;
    OBJECT_ATTRIBUTES KeyAttributes;
    HANDLE KeyHandle;

    RtlInitUnicodeString(&uKeyName, PROG_PATH);
    InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes, 0, NULL,
     REG_OPTION_NON_VOLATILE, &DW);
    #if DBG
     DbgPrint("M: ZwCreateKey %X\n", status);
    #endif
    if (status == STATUS_SUCCESS)
     {
     UNICODE_STRING uParameter;
     RtlInitUnicodeString(&uParameter, L"Data");
     status = ZwSetValueKey(KeyHandle, &uParameter, 0, REG_BINARY, SecretCode, SECR_CODE_SIZE);

     ZwClose(KeyHandle);

     dx->IsRegisterCopy = 1;
     RtlCopyMemory(dx->StartSettings->Data, SecretCode, SECR_CODE_SIZE);
     }
    }
   else
    {
    status = STATUS_INVALID_SECRET_CODE;
    }
   }
  else
   {
   status = STATUS_INVALID_SECRET_CODE_VERSION;
   }
  }


 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция нити, запускающая создание сессии
//----------------------------------------------------------------------------------------------------
VOID CreateSessionThread(IN PVOID dx)
 {
 #if DBG
  DbgPrint("M: Thread start\n");
 #endif
 CreateSession((PDRIVER_DEVICE_EXTENSION)dx);
 PsTerminateSystemThread(STATUS_SUCCESS);
 }

//----------------------------------------------------------------------------------------------------
// Функция создающая сессию
//----------------------------------------------------------------------------------------------------
VOID __stdcall CreateSession(PDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG * IsTerminal;
 MYPORT_MESSAGE Request;
 HANDLE PortHandle = 0;
 UNICODE_STRING SmApiPortStr;
 ULONG DataSize = 256;
 unsigned char * Data[256];
 SECURITY_QUALITY_OF_SERVICE SecurityQos;
 ULONG res;

 #if DBG
  DbgPrint("M: CreateSession start\n");
 #endif

 IsTerminal = (ULONG *)0xffdf02d0;
 DbgPrint("M: IsTerminal: %X\n", (*IsTerminal));
 if (dx->StartSettings->GlobTerminalVar != 0xFFFFFFFF)
  *IsTerminal = dx->StartSettings->GlobTerminalVar;
 #if DBG
  DbgPrint("M: IsTerminal: %X\n", (*IsTerminal));
  DbgPrint("=========================\n");
 #endif

 dx->GlobStatus = STATUS_SUCCESS;

 RtlZeroMemory(&Request, sizeof(Request));

 RtlInitUnicodeString(&SmApiPortStr, L"\\SmApiPort");

 RtlZeroMemory(&SecurityQos, sizeof(SecurityQos));
 SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
 SecurityQos.ImpersonationLevel = SecurityImpersonation;
 SecurityQos.Length = sizeof(SecurityQos);

 res = ZwConnectPort(&PortHandle, &SmApiPortStr, &SecurityQos, 0,
  0, 0, Data, &DataSize);

 if (NT_SUCCESS(res))
  {
  dx->InSessionStart = TRUE;

  Request.DataLength = 0x0118;
  Request.TotalLength = 0x0130;
  Request.Type = 0;
  Request.VirtualRangesOffset = 0;

  //Фейковая проверка. Для ограничения по количеству запусков в демо-версии
  if (dx->CanDemoStartSession2 == 0x1)
   {
   Request.param1 = 0x05;
   Request.param2 = 0xffffffff;
   }
  else
   {
   Request.param1 = 0x00;
   Request.param2 = 0x00;
   }

  Request.ClientId.UniqueProcess = 0;
  Request.ClientId.UniqueThread = 0;
  res = ZwRequestWaitReplyPort(PortHandle, (PPORT_MESSAGE)&Request, (PPORT_MESSAGE)&Request);
  if (! NT_SUCCESS(res))
   {
   dx->GlobStatus = ParseError(STATUS_CANT_SEND_MESSAGE, res);
   }
  #if DBG
   DbgPrint("M: res=%X\n", res);
   DbgPrint("M: result=%X\n", Request.result);
  #endif

  if (Request.result)
   {
   dx->GlobStatus = ParseError(STATUS_SMSS_RETURN_ERROR, Request.result);
   }
  ZwClose(PortHandle);

  dx->InSessionStart = FALSE;
  }
 else
  {
  dx->GlobStatus = ParseError(STATUS_CANT_OPEN_SMAPIPORT, res);
  }
 #if DBG
  DbgPrint("M: CreateSession finish\n");
 #endif

 return;
 }

//----------------------------------------------------------------------------------------------------
// Функция создающая ссылку на событие для отслеживания завершения работы
//----------------------------------------------------------------------------------------------------
NTSTATUS CreateShutdownLink()
 {
 NTSTATUS status;

 UNICODE_STRING uSymLinkName;
 UNICODE_STRING uEventName;
 RtlInitUnicodeString(&uEventName, CANCLOSE_EVENT_NAME);
 RtlInitUnicodeString(&uSymLinkName, CANCLOSE_EVENT_SYMLINK_NAME);
 status = IoCreateSymbolicLink(&uSymLinkName, &uEventName);

 RtlInitUnicodeString(&uEventName, WAIT_ANSWERS_CANCLOSE_EVENT_NAME);
 RtlInitUnicodeString(&uSymLinkName, WAIT_ANSWERS_CANCLOSE_EVENT_SYMLINK_NAME);
 status = IoCreateSymbolicLink(&uSymLinkName, &uEventName);

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция проверки, можно ли завершать работу системы
//----------------------------------------------------------------------------------------------------
ULONG CanShutdown()
 {
 NTSTATUS status;
 ULONG i;
 ULONG LoggedCount = 0;

 PDRIVER_DEVICE_EXTENSION dx = GetDx();

 for (i = 0; i < dx->LastWorkstation + 1; i ++)
  if (dx->IsLogged[i])
   LoggedCount ++;

  #if DBG
   DbgPrint("M: dx->LastWorkstation %X\n", dx->LastWorkstation);
  #endif

 if (dx->LastWorkstation && dx->SessionsStarted && (LoggedCount > 1) && !dx->TotalCanContinueShutdown) //если больше одной станции включено и залогинено, или ранее все не соглашались завершить работу
  {
  HANDLE Event;
  UNICODE_STRING uEventName;
  OBJECT_ATTRIBUTES EventAttributes;

  RtlInitUnicodeString(&uEventName, CANCLOSE_EVENT_NAME);
  InitializeObjectAttributes(&EventAttributes, &uEventName , 0, NULL, NULL);
  status = ZwOpenEvent(&Event, EVENT_ALL_ACCESS, &EventAttributes);
  #if DBG
   DbgPrint("M: ZwOpenEvent %X\n", status);
  #endif

  if (status == STATUS_SUCCESS)
   {
   LONG Prev;
   HANDLE WaitEvent;

   status = ZwSetEvent(Event, &Prev);
   #if DBG
    DbgPrint("M: ZwSetEvent %X\n", status);
    DbgPrint("M: Prev %X\n", Prev);
   #endif
   if (Prev == 0)
    {
    dx->CanContinueShutdown = TRUE;
    dx->ShutdownInitiatorCancel = FALSE;
    dx->ShutdownInitiator = GetWorkStationNumber(dx);

    #if DBG
     DbgPrint("M: Set dx->CanContinueAnswers to FALSE\n");
    #endif

    for (i = 0; i < 10; i ++)
     dx->CanContinueAnswers[i] = FALSE; //обнулим счётчик полученных ответов

    RtlInitUnicodeString(&uEventName, WAIT_ANSWERS_CANCLOSE_EVENT_NAME);
    InitializeObjectAttributes(&EventAttributes, &uEventName , 0, NULL, NULL);
    status = ZwOpenEvent(&WaitEvent, EVENT_ALL_ACCESS, &EventAttributes);
    #if DBG
     DbgPrint("M: ZwOpenEvent WAIT_ANSWERS_CANCLOSE_EVENT_NAME %X\n", status);
    #endif
    if (status == STATUS_SUCCESS)
     {
     ZwClearEvent(WaitEvent);
     //ожидаем опроса всех станций
     status = ZwWaitForSingleObject(WaitEvent,TRUE, NULL);
     #if DBG
      DbgPrint("M: ZwWaitForSingleObject %X\n", status);
     #endif

     ZwClearEvent(Event);

     ZwClose(WaitEvent);
     }
    }
   else
    {
    dx->CanContinueShutdown = FALSE;
    DbgPrint("M: Alse wait shutdown...\n");
    }

   ZwClose(Event);
   }

  DbgPrint("M: dx->CanContinueShutdown %X\n", dx->CanContinueShutdown);
  DbgPrint("M: dx->ShutdownInitiatorCancel %X\n", dx->ShutdownInitiatorCancel);
  if (dx->CanContinueShutdown)
   return 0;
  else
   {
   if (dx->ShutdownInitiatorCancel)
    return 1;
   else
    return 2;
   }
  }
 else
  return 0;
 }

//----------------------------------------------------------------------------------------------------
// CompleteIrp: Устанавливает IoStatus и завершает обработку IRP
// Первый аргумент - указатель на объект FDO.
//----------------------------------------------------------------------------------------------------
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG info)
 {
 Irp->IoStatus.Status = status;
 Irp->IoStatus.Information = info;
 IoCompleteRequest(Irp,IO_NO_INCREMENT);
 return status;
 }

//----------------------------------------------------------------------------------------------------
// Create_File_IRPprocessing: Берет на себя обработку запросов с
// кодом IRP_MJ_CREATE.
// Аргументы:
// Указатель на объект FDO
// Указатель на структуру IRP, поступившего от Диспетчера ВВ
//----------------------------------------------------------------------------------------------------
NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
 {
 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
 #if DBG
  DbgPrint("M: Create File is %ws", &(IrpStack->FileObject->FileName.Buffer));
 #endif
 return CompleteIrp(Irp,STATUS_SUCCESS,0); // Успешное завершение
 }

//----------------------------------------------------------------------------------------------------
// Close_File_IRPprocessing: Берет на себя обработку запросов с
// кодом IRP_MJ_CLOSE.
// Аргументы:
// Указатель на объект нашего FDO
// Указатель на структуру IRP, поступившего от Диспетчера ввода/вывода
//----------------------------------------------------------------------------------------------------
NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
 #if DBG
 // Задаем печать отладочных сообщений - если сборка отладочная
 DbgPrint("M: In Close handler.\n");
 #endif
return CompleteIrp(Irp,STATUS_SUCCESS,0);// Успешное завершение
}


//----------------------------------------------------------------------------------------------------
// DeviceControlRoutine: обработчик IRP_MJ_DEVICE_CONTROL запросов
// Аргументы:
// Указатель на объект нашего FDO
// Указатель на структуру IRP, поступившего от Диспетчера ВВ
// Возвращает:  STATUS_XXX
//----------------------------------------------------------------------------------------------------
NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
 {
 NTSTATUS status = STATUS_SUCCESS;
 ULONG i, j;
 ULONG BytesTxd = 0; // Число переданных/полученных байт
 PIO_STACK_LOCATION IrpStack=IoGetCurrentIrpStackLocation(Irp);

 //Получаем указатель на расширение устройства
 PDRIVER_DEVICE_EXTENSION dx = (PDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
 //-------------------------------
 // Выделяем из IRP собственно значение IOCTL кода, по поводу
 // которого случился вызов:
 ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

 // Общие переменные
 ULONG bufsize;
 ULONG OutputLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
 ULONG InputLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

 #if DBG
  DbgPrint("M: In DeviceControlRoutine (fdo = %X)\n",fdo);
  DbgPrint("M: DeviceIoControl: IOCTL %x\n", ControlCode );
  DbgPrint("M: Buffer outlength %d\n", OutputLength);
  DbgPrint("M: Buffer inlength %d\n", InputLength);
 #endif

 // Диспетчеризация по IOCTL кодам:
 switch(ControlCode)
  {
  case IOCTL_START_NEW_SESSION:
   {
   #if DBG
    DbgPrint("M: IOCTL_START_NEW_SESSION\n");
   #endif

   #if DEMO
   if (TRUE)
    {
   #else
   if (dx->IsRegisterCopy)
    {
   #endif
    if (!dx->SessionsStarted && !dx->HaveAllConsoleDevices &&
      (dx->CanDemoStartSession1 == 0x4)) //если сессии незапущены и в наличии все устройства для консольной сессии, и не превышено количество демо-запусков
     {
     for (i = 1; i < dx->StartSettings->WorkstationsCount; i ++)
      {
      HANDLE thread_handle = NULL;
      NTSTATUS res = PsCreateSystemThread(&thread_handle, 0, NULL, 0, NULL, CreateSessionThread, dx);
      #if DBG
       DbgPrint("M: PsCreateSystemThread = %d\n",res);
      #endif

      if (NT_SUCCESS(res))
       {
       PKTHREAD pThreadObject;

       NTSTATUS res2 = ObReferenceObjectByHandle(thread_handle, THREAD_ALL_ACCESS, NULL, KernelMode,
        (PVOID *)&pThreadObject, NULL);

       if(NT_SUCCESS(res2))
        {
        // Ожидаем окончания потока hThread
        KeWaitForSingleObject( (PVOID)pThreadObject, Suspended, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        ObDereferenceObject(pThreadObject);
        }
       #if DBG
        DbgPrint("M: dx->LastWorkstation = %d\n", dx->LastWorkstation );
       #endif
       //создадим событие для отслеживания завершения работы
       CreateShutdownLink();

       dx->SessionsStarted = TRUE;

       status = dx->GlobStatus;
       }
      else
       {
       status = ParseError(STATUS_CANT_CREATE_SS_THREAD, res);
       }
      }
     }
    else
     {
     status = STATUS_INVALID_PARAMETER;
     #if DBG
      DbgPrint("M: Sessions already started\n");
     #endif
     }

    }
   else
    {
    status = STATUS_VERSION_NOT_REGISTER;
    }

   break;
   }

  case IOCTL_GET_VIDEO_DEVICE_INFO:
   {
   PVIDEO_DEVICES_INFO DevicesInfo;

   #if DBG
    DbgPrint("M: IOCTL_GET_VIDEO_DEVICE_INFO\n");
   #endif

   bufsize = sizeof(VIDEO_DEVICES_INFO);

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_VIDEO, STATUS_INVALID_PARAMETER);
    break;
    }

   DevicesInfo = (PVIDEO_DEVICES_INFO)Irp->AssociatedIrp.SystemBuffer;
   BytesTxd = bufsize;
   RtlZeroMemory(DevicesInfo, bufsize);
   status = GetVideoDeviceInfo(DevicesInfo, dx);

   break;
   }

  case IOCTL_GET_KEYBOARD_DEVICE_INFO:
   {
   PINPUT_DEVICES_INFO DevicesInfo;

   #if DBG
    DbgPrint("M: IOCTL_GET_KEYBOARD_DEVICE_INFO\n");
   #endif

   bufsize = sizeof(INPUT_DEVICES_INFO);

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_INPUT, STATUS_INVALID_PARAMETER);
    break;
    }

   DevicesInfo = (PINPUT_DEVICES_INFO)Irp->AssociatedIrp.SystemBuffer;
   BytesTxd = bufsize;
   RtlZeroMemory(DevicesInfo, bufsize);
   status = GetInputDeviceInfo(DevicesInfo, dx, Keyboard);

   break;
   }

  case IOCTL_GET_POINTER_DEVICE_INFO:
   {
   PINPUT_DEVICES_INFO DevicesInfo;

   #if DBG
    DbgPrint("M: IOCTL_GET_KEYBOARD_DEVICE_INFO\n");
   #endif

   bufsize = sizeof(INPUT_DEVICES_INFO);

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_INPUT, STATUS_INVALID_PARAMETER);
    break;
    }

   DevicesInfo = (PINPUT_DEVICES_INFO)Irp->AssociatedIrp.SystemBuffer;
   BytesTxd = bufsize;
   RtlZeroMemory(DevicesInfo, bufsize);
   status = GetInputDeviceInfo(DevicesInfo, dx, Pointer);

   break;
   }


  case IOCTL_GET_HID_DEVICE_INFO:
   {
   PHID_DEVICES_INFO DevicesInfo;

   #if DBG
    DbgPrint("M: IOCTL_GET_HID_DEVICE_INFO\n");
   #endif

   bufsize = sizeof(HID_DEVICES_INFO);

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_INPUT, STATUS_INVALID_PARAMETER);
    break;
    }

   DevicesInfo = (PHID_DEVICES_INFO)Irp->AssociatedIrp.SystemBuffer;
   BytesTxd = bufsize;
   RtlZeroMemory(DevicesInfo, bufsize);
   status = GetHIDDeviceInfo(DevicesInfo, dx);

   break;
   }

  case IOCTL_GET_SETTINGS:
   {
   PSETTINGS Settings;

   #if DBG
    DbgPrint("M: IOCTL_GET_SETTINGS\n");
   #endif

   bufsize = sizeof(SETTINGS);

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_SETTING, STATUS_INVALID_PARAMETER);
    break;
    }

   Settings = (PSETTINGS)Irp->AssociatedIrp.SystemBuffer;
   BytesTxd = bufsize;
   RtlZeroMemory(Settings, bufsize);
   status = GetSettings(Settings, dx);

   break;
   }

  case IOCTL_GET_START_SETTINGS:
   {
   PSETTINGS Settings;

   #if DBG
    DbgPrint("M: IOCTL_GET_START_SETTINGS\n");
   #endif

   bufsize = sizeof(SETTINGS);

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_SETTING, STATUS_INVALID_PARAMETER);
    break;
    }

   Settings = (PSETTINGS)Irp->AssociatedIrp.SystemBuffer;
   BytesTxd = bufsize;
   RtlZeroMemory(Settings, bufsize);
   status = GetStartSettings(Settings, dx);

   break;
   }

  case IOCTL_SET_SETTINGS:
   {
   PSETTINGS Settings;

   #if DBG
    DbgPrint("M: IOCTL_SET_SETTINGS\n");
   #endif

   bufsize = sizeof(SETTINGS);

   if (InputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_SETTING, STATUS_INVALID_PARAMETER);
    break;
    }

   #if DBG
    DbgPrint("M: SystemBuffer %X\n", Irp->AssociatedIrp.SystemBuffer);
   #endif

   Settings = (PSETTINGS)Irp->AssociatedIrp.SystemBuffer;
   status = SetSettings(Settings, dx);
   break;
   }

  case IOCTL_GET_START_TYPE:
   {
   MY_KEY_VALUE_PARTIAL_INFORMATION KeyInformation;
   ULONG DW;
   UNICODE_STRING uKeyName;
   OBJECT_ATTRIBUTES KeyAttributes;
   HANDLE KeyHandle;

   #if DBG
    DbgPrint("M: IOCTL_GET_START_TYPE\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_SETTING, STATUS_INVALID_PARAMETER);
    break;
    }

   #if DBG
    DbgPrint("M: SystemBuffer %X\n", Irp->AssociatedIrp.SystemBuffer);
   #endif

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = 0;
   RtlInitUnicodeString(&uKeyName, SERVICE_PATH);
   InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
   status = ZwOpenKey(&KeyHandle, GENERIC_READ, &KeyAttributes);
   #if DBG
    DbgPrint("M: ZwOpenKey %X\n", status);
   #endif

   if (status == STATUS_SUCCESS)
    {
    UNICODE_STRING uStartType;
    RtlInitUnicodeString(&uStartType, L"Start");
    RtlZeroMemory(KeyInformation.Data, 1024);
    status = ZwQueryValueKey(KeyHandle, &uStartType, KeyValuePartialInformation, &KeyInformation,
     1024, &DW);
    if (status == STATUS_SUCCESS)
     *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = *((ULONG *)KeyInformation.Data);
    }
   BytesTxd = bufsize;

   break;
   }

  case IOCTL_SET_START_TYPE:
   {
   UNICODE_STRING uKeyName;
   OBJECT_ATTRIBUTES KeyAttributes;
   HANDLE KeyHandle;

   #if DBG
    DbgPrint("M: IOCTL_SET_START_TYPE\n");
   #endif

   bufsize = 4;

   if (InputLength < bufsize)
    {
    status = ParseError(STATUS_INVALID_BUFSIZE_FOR_SETTING, STATUS_INVALID_PARAMETER);
    break;
    }

   #if DBG
    DbgPrint("M: SystemBuffer %X\n", Irp->AssociatedIrp.SystemBuffer);
   #endif

   RtlInitUnicodeString(&uKeyName, SERVICE_PATH);
   InitializeObjectAttributes(&KeyAttributes, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
   status = ZwOpenKey(&KeyHandle, GENERIC_READ, &KeyAttributes);
   #if DBG
    DbgPrint("M: ZwOpenKey %X\n", status);
   #endif

   if (status == STATUS_SUCCESS)
    {
    UNICODE_STRING uStartType;
    RtlInitUnicodeString(&uStartType, L"Start");
    status = ZwSetValueKey(KeyHandle, &uStartType, 0, REG_DWORD, Irp->AssociatedIrp.SystemBuffer, 4);
    }

   break;
   }

  case IOCTL_SET_CONTINUE_SHUTDOWN:
   {
   ULONG CanClose = *((ULONG*)Irp->AssociatedIrp.SystemBuffer);
   ULONG WorkStationNumber = GetWorkStationNumber(dx);

   #if DBG
    DbgPrint("M: IOCTL_SET_CONTINUE_SHUTDOWN\n");
   #endif

   bufsize = 4;

   if (InputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   #if DBG
    DbgPrint("M: SystemBuffer %X\n", Irp->AssociatedIrp.SystemBuffer);
   #endif

   if (!dx->CanContinueAnswers[WorkStationNumber - 1]) //если не повторный ответ од одного и того же рабочего места
    {
    UNICODE_STRING  uEventName;
    OBJECT_ATTRIBUTES EventAttributes;
    HANDLE WaitEvent;

    #if DBG
     DbgPrint("M: CanClose %X\n", CanClose);
    #endif

    dx->CanContinueAnswers[WorkStationNumber - 1] = 1;
    dx->CanContinueShutdown &= CanClose;

    if ((dx->ShutdownInitiator == WorkStationNumber) && !CanClose) //если инициатор отменил завершение, то не будем его вылогинивать
     dx->ShutdownInitiatorCancel = TRUE;

    RtlInitUnicodeString(&uEventName, WAIT_ANSWERS_CANCLOSE_EVENT_NAME);
    InitializeObjectAttributes(&EventAttributes, &uEventName , 0, NULL, NULL);
    status = ZwOpenEvent(&WaitEvent, EVENT_ALL_ACCESS, &EventAttributes);
    #if DBG
     DbgPrint("M: ZwOpenEvent WAIT_ANSWERS_CANCLOSE_EVENT_NAME %X\n", status);
    #endif
    if (status == STATUS_SUCCESS)
     {
     BOOLEAN IsAllAnswer = TRUE;
     ULONG AnswersCount = 0; //количество ответивших
     for (i = 0; i < dx->LastWorkstation + 1; i ++)
      {
      IsAllAnswer &= dx->CanContinueAnswers[i];
      if (dx->CanContinueAnswers[i])
       AnswersCount ++;
      }


     #if DBG
      DbgPrint("M: AnswersCount %X\n", AnswersCount);
      DbgPrint("M: dx->LastWorkstation %X\n", dx->LastWorkstation);
      DbgPrint("M: dx->ShutdownInitiator %X\n", dx->ShutdownInitiator);
      DbgPrint("M: dx->CanContinueAnswers[dx->ShutdownInitiator - 1] %X\n", dx->CanContinueAnswers[dx->ShutdownInitiator - 1]);
     #endif
     //если ответили все, кроме одного, и этот один - инициатор завершения работы, то не будем дожидаться ответа от него
     if ((AnswersCount == dx->LastWorkstation) && (!dx->CanContinueAnswers[dx->ShutdownInitiator - 1]))
      {
      IsAllAnswer = TRUE;
      dx->CanContinueAnswers[dx->ShutdownInitiator - 1] = 1;
      }

     #if DBG
      DbgPrint("M: WorkStationNumber %X\n", WorkStationNumber);
      DbgPrint("M: IsAllAnswer %X\n", IsAllAnswer);
      DbgPrint("M: dx->CanContinueShutdown %X\n", dx->CanContinueShutdown);
     #endif

     if (!CanClose || IsAllAnswer)
      {
      LONG Prev;
      status = ZwSetEvent(WaitEvent, &Prev);
      if (dx->CanContinueShutdown)
       dx->TotalCanContinueShutdown = TRUE;
      #if DBG
       DbgPrint("M: ZwSetEvent WaitEvent %X\n", status);
      #endif
      }

     ZwClose(WaitEvent);
     }
    }

   break;
   }

  //является ли текущая станция инициатором завершения работы
  case IOCTL_GET_IS_CURRENT_SHUTDOWN:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_IS_CURRENT_SHUTDOWN\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   if (dx->ShutdownInitiator == GetWorkStationNumber(dx))
    *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = 1;
   else
    *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = 0;

   BytesTxd = bufsize;

   break;
   }

  //установить, является ли пользователь залогиненым
  case IOCTL_SET_IS_LOGGED:
   {
   ULONG WorkStationNumber;

   #if DBG
    DbgPrint("M: IOCTL_SET_IS_LOGGED\n");
   #endif

   bufsize = 4;

   if (InputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   WorkStationNumber = GetWorkStationNumber(dx);
   dx->IsLogged[WorkStationNumber - 1] = (BOOLEAN)*((ULONG *)Irp->AssociatedIrp.SystemBuffer);

   break;
   }

  //получить номер рабочего места
  case IOCTL_GET_WORKSTATION_NUMBER:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_WORKSTATION_NUMBER\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = GetWorkStationNumber(dx);
   BytesTxd = bufsize;

   break;
   }

  //узнать стартовал ли сервис при загрузке
  case IOCTL_GET_START_ON_BOOT:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_START_ON_BOOT\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = dx->StartOnBoot;
   BytesTxd = bufsize;

   break;
   }

  //узнать, запущены ли сессии
  case IOCTL_GET_SESSIONS_STARTED:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_SESSIONS_STARTED\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = dx->SessionsStarted;
   BytesTxd = bufsize;

   break;
   }

  //узнать, есть ли все устройства для консоли
  case IOCTL_GET_HAVE_ALL_CONSOLE_DEVICES:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_HAVE_ALL_CONSOLE_DEVICES\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = dx->HaveAllConsoleDevices;
   BytesTxd = bufsize;

   break;
   }

  //узнать, демонстрационная ли версия
  case IOCTL_GET_IS_DEMO:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_IS_DEMO\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   #if DEMO
    *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = 1;
   #else
    *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = 0;
   #endif
   BytesTxd = bufsize;

   break;
   }

  //узнать, зарегистрированная ли копия
  case IOCTL_GET_IS_REGISTER_COPY:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_IS_REGISTER_COPY\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = dx->IsRegisterCopy;
   BytesTxd = bufsize;

   break;
   }

  //получить AES ключ для шифрования очень секретного участка кода
  case IOCTL_GET_AES_KEY:
   {
   BYTE Key[32];
   ULONG Seed;
   ULONG * Key32;
   BYTE * Buffer;
   char chiphertext[] = "EWQ3R8TYUIOP4ASDF52GHJKLZXCVBNM1";

   #if DBG
   // DbgPrint("M: IOCTL_GET_AES_KEY\n");
   #endif

   bufsize = AES_KEY_SIZE * 2;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   status = GetAESKey(Key);
   Key32 = (ULONG *)Key;
   Buffer = (BYTE *)Irp->AssociatedIrp.SystemBuffer;

   Key32[AES_KEY_SIZE / 4 - 1] = 0;
   Seed = 0x00;

   for (i = 0; i < (AES_KEY_SIZE / 4 - 1); i ++)
    Seed += Key32[i];

   //*((BYTE*)&Seed) = 0x27;

   Key32[AES_KEY_SIZE / 4 - 1] = Seed;

   #if DBG
    DbgPrint("M: k1 %X\n", Key32[1]);
   #endif

   for (i = 0; i < (AES_KEY_SIZE / 4 - 1); i ++)
    Key32[i] ^= Key32[AES_KEY_SIZE / 4 - 1];

   #if DBG
    DbgPrint("M: k11 %X\n", Key32[1]);
    DbgPrint("M: k12 %X\n", Key32[AES_KEY_SIZE / 4 - 1]);
   #endif

   for (i = 0, j = 0; i < AES_KEY_SIZE; i ++, j += 2)
    {
    Buffer[j] = chiphertext[(Key[i] / 0x10) + ((RtlRandomEx(&Seed)>0x7FFFFFFF)?16:0) ];
    Buffer[j + 1] = chiphertext[(Key[i] % 0x10) + ((RtlRandomEx(&Seed)>0x7FFFFFFF)?16:0) ];
    }

   BytesTxd = bufsize;

   break;
   }

  //сохранить очень секретный код
  case IOCTL_SET_SECRET_CODE:
   {
   #if DBG
    DbgPrint("M: IOCTL_SET_SECRET_CODE\n");
   #endif

   bufsize = SECR_CODE_SIZE;

   if (InputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   status = SetSecretCode((BYTE *)Irp->AssociatedIrp.SystemBuffer, dx);
   break;
   }

  //Получить реальный номер сессии
  case IOCTL_GET_REAL_SESSION_ID:
   {
   #if DBG
    DbgPrint("M: IOCTL_GET_REAL_SESSION_ID\n");
   #endif

   bufsize = 4;

   if (OutputLength < bufsize)
    {
    status = STATUS_INVALID_PARAMETER;
    break;
    }

   *((ULONG *)Irp->AssociatedIrp.SystemBuffer) = PsGetCurrentProcessSessionId();
   BytesTxd = bufsize;

   break;
   }

  // Ошибочный запрос (код IOCTL, который не обрабатывается):
  default: status = STATUS_INVALID_DEVICE_REQUEST;
  }

 #if DBG
  DbgPrint("M: status %X\n", status);
 #endif
 return CompleteIrp(Irp, status, BytesTxd); // Завершение IRP
 }

//----------------------------------------------------------------------------------------------------
// UnloadRoutine: Выгружает драйвер, освобождая оставшиеся объекты
// Вызывается системой, когда необходимо выгрузить драйвер.
// Как и процедура AddDevice, регистрируется иначе чем
// все остальные рабочие процедуры и не получает никаких IRP.
// Arguments:  указатель на объект драйвера
//----------------------------------------------------------------------------------------------------
VOID UnloadRoutine(IN PDRIVER_OBJECT pDriverObject)
 {
 PDEVICE_OBJECT pNextDevObj;
 ULONG i;
 PDRIVER_DEVICE_EXTENSION dx = (PDRIVER_DEVICE_EXTENSION)pDriverObject->DeviceObject;

 #if DBG
  DbgPrint("M: In Unload Routine\n");
 #endif

 if (dx->StartOnBoot)
  UnHookNtCalls(dx);

 pNextDevObj = pDriverObject->DeviceObject;

 for(i = 0; pNextDevObj != NULL; i++)
  {
  PDRIVER_DEVICE_EXTENSION dx =
   (PDRIVER_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;
  // сохраняем указатель:
  pNextDevObj = pNextDevObj->NextDevice;

  #if DBG
   DbgPrint("M: Deleted device (%d) : pointer to FDO = %X\n", i, dx->fdo);
   DbgPrint("M: Deleted symlink = %ws\n", dx->SymLinkName.Buffer);
  #endif

  if (dx->StartSettings)
   ExFreePool(dx->StartSettings);

  IoDeleteSymbolicLink(&dx->SymLinkName);
  IoDeleteDevice(dx->fdo);
  }
 }
#pragma code_seg() // end PAGE section



