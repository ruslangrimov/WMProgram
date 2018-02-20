#include "ntcallhooks.h"
#include "Driver.h"

#pragma warning (disable : 4748)
//----------------------------------------------------------------------------------------------------
// Функция-перехватчик создания события
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtCreateEvent(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE  EventType,
    IN BOOLEAN  InitialState
 )
 {
 BOOLEAN isTrue = 0;
 ULONG i;
 NTSTATUS res;
 PCHAR processname;

 processname = GetProcessName();
 if ((!_stricmp("smss.exe", processname)))
  {
  if (ObjectAttributes)
   {
   if (ObjectAttributes->ObjectName)
    {
    if (!MyCompareUnicodeStringI(ObjectAttributes->ObjectName, L"\\UniqueSessionIdEvent"))
     {
     //это одно из самых первых мест, при начале сессии, потому тут делать будем то - что нельзя при загрузке драйвера
     //контекст процесса - smss.exe, нулевая сессия
     PDRIVER_DEVICE_EXTENSION dx = GetDx();
     if (dx)
      {
      //объявляем тут все переменные, что будут участвовать в шифрованом коде
      ULONG curEIP = 0;
      BYTE m2[] = {0x01, 0xA7, 0x02, 0x38, 0xC8, 0xAD, 0x11, 0x17};

      void *end = 0;
      BYTE *begin = 0;
      WCHAR Buffer[32];
      ULONG I = 0;
      PDEVICE_OBJECT pCurDevice = NULL;

      WCHAR wstr1[] = L"KeyboardClass%d";
      WCHAR wstr2[] = L"PointerClass%d";
      char str1[] = "M: Buffer %ws\n";
      char str2[] = "M: dx->KeyboardsPDO[%d]=%X\n";
      char str3[] = "M: Buffer %ws\n";
      char str4[] = "M: dx->PointersPDO[%d]=%X\n";
      typedef NTSTATUS (*PSearchDevice)(PDEVICE_OBJECT *pDeviceObject, PCWSTR cwDeviceName);
      PSearchDevice LocSearchDevice = SearchDevice;
      typedef int (*p_swprintf)(wchar_t *Buffer, const wchar_t *wstr, ...);
      p_swprintf my_swprintf = swprintf;
      typedef PDEVICE_OBJECT (*PIoGetDeviceAttachmentBaseRef)(IN PDEVICE_OBJECT  DeviceObject);
      PIoGetDeviceAttachmentBaseRef MyIoGetDeviceAttachmentBaseRef = IoGetDeviceAttachmentBaseRef;
      typedef ULONG (*PDbgPrint)(IN PCHAR  Format, ...);
      PDbgPrint MyDbgPrint = DbgPrint;

      unsigned char RoundKey[240];
      unsigned char Key[32] = {0};
      ULONG * out32 = NULL;
      ULONG src = 0;
      ULONG filesize = 0;
      int Nr = 256;
      int Nk = Nr / 32;

      ULONG OldLastWorkstation;
      PVIDEO_DEVICES_INFO VideoDevicesInfo;

      //определим, в наличии ли устройства для консольной сессии
      BOOLEAN HaveConsoleVideo = FALSE;
      BOOLEAN HaveConsoleKeyboard = FALSE;
      BOOLEAN HaveConsolePointer = FALSE;

      //Бредятина, чтобы сбить команды при дизассамблировании
      if (dx->StartSettings->WorkstationsCount > 100)
       {
       _asm
        {
        _emit 0x01
        _emit 0x02
        _emit 0x07
        _emit 0xA2
        _emit 0x4A
        _emit 0xA2
        _emit 0x12
        _emit 0x78
        }
       }
      //

      //установка ограничений по запускам для демо-версии

      //нужно в дальнейшем при проверке количества запусков
      OldLastWorkstation = dx->LastWorkstation;

      //в этой функции скрыто проверяется количество пусков
      VideoDevicesInfo = (PVIDEO_DEVICES_INFO)ExAllocatePool(NonPagedPool, sizeof(VIDEO_DEVICES_INFO ));
      GetVideoDeviceInfo(VideoDevicesInfo, dx);

      #if DEMO
       if (dx->LastWorkstation > 10)
        {
        dx->CanDemoStartSession1 = dx->LastWorkstation;
        dx->LastWorkstation = OldLastWorkstation;
        }
       else
        dx->CanDemoStartSession1 = 0x4;
      #endif
      //
      _asm
       {
       call label
       label:
       pop eax //узнаем адрес возврата
       mov curEIP, eax
       }
      end = (void *)(curEIP + arrarr((BYTE *)curEIP, 1000, m2, 8) + 8);

      #if INCLUDE_SECR_CODE
       //начало скрытого кода
       #if !DEMO
       _asm
        {
        _emit 0x45
        _emit 0x9A
        _emit 0x01
        _emit 0x02
        _emit 0x03
        _emit 0xFA
        _emit 0xC3
        _emit 0xA7
        }
       #endif
       //

       //собственно секретный участок кода
       //узнаем нижнее Device PDO для устройств ввода
       for (I = 0; I < 10; I++)
        {
        my_swprintf(Buffer, wstr1, I);
        pCurDevice = NULL;
        LocSearchDevice(&pCurDevice, Buffer);
        //#if DBG
        // MyDbgPrint(str1, Buffer);
        //#endif
        if (pCurDevice)
         {
         dx->KeyboardsPDO[I] = MyIoGetDeviceAttachmentBaseRef(pCurDevice);
         //#if DBG
         // MyDbgPrint(str2, I, dx->KeyboardsPDO[I]);
         //#endif
         }

        my_swprintf(Buffer, wstr2, I);
        pCurDevice = NULL;
        LocSearchDevice(&pCurDevice, Buffer);
        //#if DBG
        // MyDbgPrint(str3, Buffer);
        //#endif
        if (pCurDevice)
         {
         dx->PointersPDO[I] = MyIoGetDeviceAttachmentBaseRef(pCurDevice);
         //#if DBG
         // MyDbgPrint(str4, I, dx->PointersPDO[I]);
         //#endif
         }
        }

       #if DEMO

       #else
        dx->CanDemoStartSession1 = 0x4;
        dx->CanDemoStartSession2 = 0x1;
       #endif
       //собственно конец секретного участка

       _asm
        {
        jmp end
        }
      #else
       begin = (BYTE *)ExAllocatePool(NonPagedPool, SECR_CODE_SIZE);
       memcpy(begin, dx->StartSettings->Data, SECR_CODE_SIZE);

       //расшифровка кода
       Nr = 256;
       Nk = Nr / 32;
       Nr = Nk + 6;

       out32 = (ULONG *)begin;
       GetAESKey(Key);

       KeyExpansion(Nk, Nr, RoundKey, Key, Rcon);
       for (I = 0; I < SECR_CODE_SIZE; I += 16)
        InvCipher(Nr, &dx->StartSettings->Data[I], &begin[I], RoundKey);

       filesize = out32[SECR_CODE_SIZE / 4 - 1];

       if (filesize < SECR_CODE_SIZE)
        {
        for (I = 0; I < filesize; I ++)
         src += (BYTE)begin[I];
        }
       //конец расшифровки

       if ((out32[SECR_CODE_SIZE / 4 - 3] == VERSION) && (filesize < SECR_CODE_SIZE) && (src == out32[SECR_CODE_SIZE / 4 - 2]))
        {
        /*DbgPrint("M: begin %X\n", begin);
        for (I = 0; I < SECR_CODE_SIZE; I ++)
         DbgPrint("M: begin[%d] %X\n", I, begin[I]);*/
        dx->IsRegisterCopy = 1;

        _asm
         {
         mov eax, begin
         add eax, 08h
         jmp eax
         }
        }

       _asm
        {
        jmp end
        }
      #endif

      //
      _asm
       {
       _emit 0x01
       _emit 0xA7
       _emit 0x02
       _emit 0x38
       _emit 0xC8
       _emit 0xAD
       _emit 0x11
       _emit 0x17
       }

      #if INCLUDE_SECR_CODE

      #else
       ExFreePool(begin);
      #endif
      //конец скрытого кода

      //находим PDO для HID устройств
      UpdateHidsPDO(dx);

      for (i = 0; i < VideoDevicesInfo->iDeviceCount; i ++)
       HaveConsoleVideo |= (dx->StartSettings->Video[VideoDevicesInfo->VideoDevices[i].VideoNumber] == 1);

      ExFreePool(VideoDevicesInfo);

      if (HaveConsoleVideo || dx->DisableHostDeviceCheck)
       {
       PINPUT_DEVICES_INFO InputDevicesInfo = (PINPUT_DEVICES_INFO)ExAllocatePool(NonPagedPool, sizeof(INPUT_DEVICES_INFO ));
       GetInputDeviceInfo(InputDevicesInfo, dx, Keyboard);

       for (i = 0; i < InputDevicesInfo->iDeviceCount; i ++)
        HaveConsoleKeyboard |= (dx->StartSettings->Keyboards[InputDevicesInfo->InputDevices[i].InputNumber] == 1);

       ExFreePool(InputDevicesInfo);

       if (HaveConsoleKeyboard || dx->DisableHostDeviceCheck)
        {
        PINPUT_DEVICES_INFO InputDevicesInfo = (PINPUT_DEVICES_INFO)ExAllocatePool(NonPagedPool, sizeof(INPUT_DEVICES_INFO ));
        GetInputDeviceInfo(InputDevicesInfo, dx, Pointer);

        for (i = 0; i < InputDevicesInfo->iDeviceCount; i ++)
         HaveConsolePointer |= (dx->StartSettings->Pointers[InputDevicesInfo->InputDevices[i].InputNumber] == 1);

        ExFreePool(InputDevicesInfo);

        if (HaveConsolePointer || dx->DisableHostDeviceCheck)
         {}
        else
         {
         dx->HaveAllConsoleDevices = STATUS_NO_POINTER_FOR_CONCOLE;
         }
        }
       else
        {
        dx->HaveAllConsoleDevices = STATUS_NO_KEYBOARD_FOR_CONCOLE;
        }
       }
      else
       {
       dx->HaveAllConsoleDevices = STATUS_NO_VIDEO_FOR_CONCOLE;
       }
      }

     if (dx->InSessionStart)
      {
      #if DBG
       DbgPrint("M: NewNtCreateEvent\n");
       DbgPrint("M: ObjectAttributes->ObjectName: %ws\n", ObjectAttributes->ObjectName->Buffer);
       DbgPrint("M: Process: %s\n", processname);
       DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
       DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
       DbgPrint("M: =========================\n");
      #endif
      isTrue = 1;
      }
     }
    }
   }
  }

 if (isTrue)
  res = 0;
 else
  res = OldNtCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);

 return res;
 }
//----------------------------------------------------------------------------------------------------
// Функция-перехватчик создания директории объектов
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtCreateDirectoryObject(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
 )
 {
 int isTrue = 0;
 int i;
 NTSTATUS res;

 if ((PsGetCurrentProcessSessionId() != 0) && IsProgSession(PsGetCurrentProcessSessionId()))
  {
  NTSTATUS ntStatus;
  SID sidEveryone = { 0 };
  PISID CurSID;
  SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_WORLD_SID_AUTHORITY;
  PVOID Ace;
  wchar_t NewDirectoryName[64];
  PCHAR processname = GetProcessName();
  if (ObjectAttributes)
   {
   if (ObjectAttributes->ObjectName)
    {
    if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"BaseNamedObjects"))
     {
     #if DBG
      DbgPrint("M: NewNtCreateDirectoryObject\n");
      DbgPrint("M: Directory: %wZ\n", ObjectAttributes->ObjectName);
      DbgPrint("M: SecurityDescriptor: %X\n", ((SECURITY_DESCRIPTOR *)ObjectAttributes->SecurityDescriptor)->Dacl->AceCount);
     #endif

     ntStatus = RtlInitializeSid( &sidEveryone, &sidAuth, 1);
     if (!NT_SUCCESS(ntStatus))
      {
      #if DBG
       DbgPrint("M: RtlInitializeSid for everyone failed=>%08X\n",ntStatus);
      #endif
      }

     for (i = 0; i < ((SECURITY_DESCRIPTOR *)ObjectAttributes->SecurityDescriptor)->Dacl->AceCount; i ++)
      {
      ntStatus = RtlGetAce(((SECURITY_DESCRIPTOR *)ObjectAttributes->SecurityDescriptor)->Dacl, i, &Ace);
      if (!NT_SUCCESS(ntStatus))
       {
       #if DBG
        DbgPrint("M: RtlGetAce failed=>%08X\n",ntStatus);
       #endif
       }
      else
       {
       if (((PACE_HEADER)Ace)->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
        #if DBG
         DbgPrint("M: Ace->Mask=>%08X\n", ((PACCESS_ALLOWED_ACE)Ace)->Mask);
         DbgPrint("M: Ace->SidStart=>%08X\n", ((PACCESS_ALLOWED_ACE)Ace)->SidStart);
        #endif
        CurSID = (PISID) & ((PACCESS_ALLOWED_ACE)Ace)->SidStart;
        if (PsGetCurrentProcessSessionId())
         {
         if (!memcmp(CurSID->IdentifierAuthority.Value, sidAuth.Value, 6))
          {
          ((PACCESS_ALLOWED_ACE)Ace)->Mask = 0x02000F;
          #if DBG
           DbgPrint("M: Ace->NewMask=>%08X\n", ((PACCESS_ALLOWED_ACE)Ace)->Mask);
          #endif
          }
         }
        }
       }
      }

     #if DBG
      DbgPrint("M: DesiredAccess: %X\n", DesiredAccess);
      DbgPrint("M: Process: %s\n", processname);
      DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
      DbgPrint("=========================\n");
     #endif
     isTrue = 1;
     }
    else
     {
     if (IsProgSession(PsGetCurrentProcessSessionId()) && (!_stricmp("csrss.exe", processname)))
      {
      if (!MyCompareUnicodeStringI(ObjectAttributes->ObjectName, L"\\Windows\\WindowStations"))
       {
       swprintf(NewDirectoryName, L"\\Sessions\\%d\\Windows\\WindowStations", PsGetCurrentProcessSessionId());
       wcscpy(ObjectAttributes->ObjectName->Buffer, NewDirectoryName);
       ObjectAttributes->ObjectName->Length = (USHORT)wcslen(ObjectAttributes->ObjectName->Buffer) * 2;
       ObjectAttributes->ObjectName->MaximumLength = (USHORT)wcslen(ObjectAttributes->ObjectName->Buffer) * 2;
       #if DBG
        DbgPrint("M: ObjectAttributes->ObjectName: %wZ\n", ObjectAttributes->ObjectName);
        DbgPrint("M: NewNtCreateDirectoryObject\n");
        DbgPrint("M New: ObjectAttributes->ObjectName: %wZ\n", ObjectAttributes->ObjectName);
        DbgPrint("M: Process: %s\n", processname);
        DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
        DbgPrint("=========================\n");
       #endif
       isTrue = 1;
       }
      }
     }
    }
   }
  }
 res = OldNtCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
 if (isTrue)
  {
  #if DBG
   DbgPrint("M: res: %X\n",  res);
   DbgPrint("=========================\n");
  #endif
  }
 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик открытия директории объектов
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtOpenDirectoryObject(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
 )
 {
 int isTrue = 0;
 int i;
 NTSTATUS res;

 if ((PsGetCurrentProcessSessionId() != 0) && IsProgSession(PsGetCurrentProcessSessionId()))
  {
  NTSTATUS ntStatus;
  SID sidEveryone = { 0 };
  PISID CurSID;
  SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_WORLD_SID_AUTHORITY;
  PVOID Ace;

  wchar_t NewDirectoryName[64];
  PCHAR processname = GetProcessName();
  if (ObjectAttributes)
   {
   if (ObjectAttributes->ObjectName)
    {
    if (!MyCompareUnicodeStringI(ObjectAttributes->ObjectName, L"\\BaseNamedObjects"))
     {
     swprintf(NewDirectoryName, L"\\Sessions\\%d\\BaseNamedObjects", PsGetCurrentProcessSessionId());
     wcscpy(ObjectAttributes->ObjectName->Buffer, NewDirectoryName);
     ObjectAttributes->ObjectName->Length = (USHORT)wcslen(ObjectAttributes->ObjectName->Buffer) * 2;
     ObjectAttributes->ObjectName->MaximumLength = (USHORT)wcslen(ObjectAttributes->ObjectName->Buffer) * 2;
     #if DBG
      DbgPrint("M: ObjectAttributes->ObjectName: %wZ\n", ObjectAttributes->ObjectName);
      DbgPrint("M: NewNtOpenDirectoryObject\n");
      DbgPrint("M New: ObjectAttributes->ObjectName: %wZ\n", ObjectAttributes->ObjectName);
      DbgPrint("M: Process: %s\n", processname);
      DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
      DbgPrint("=========================\n");
     #endif
     isTrue = 1;
     }

    }
   }
  }

 res = OldNtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
 if (isTrue)
  {
  #if DBG
   DbgPrint("M: res: %X\n",  res);
   DbgPrint("=========================\n");
  #endif
  }
 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик открытия файла
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtOpenFile(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  ShareAccess,
    IN ULONG  OpenOptions
 )
 {
 int isTrue = 0;
 NTSTATUS res;
 if (IsProgSession(PsGetCurrentProcessSessionId()))
  {
  PCHAR processname = GetProcessName();

  if (ObjectAttributes)
   {
   if (ObjectAttributes->ObjectName)
    {
    if ((PsGetCurrentProcessSessionId() != 0) && !_stricmp("winlogon.exe", processname))
     {
     if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"lsass.exe") || MyStrUnicodeString(ObjectAttributes->ObjectName, L"services.exe"))
      {
      #if DBG
       DbgPrint("M: NewNewNtOpenFile\n");
       DbgPrint("M: File Name: %wZ\n", ObjectAttributes->ObjectName);
       DbgPrint("M: Process: %s\n", processname);
       DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
       DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
       DbgPrint("=========================\n");
      #endif
      isTrue = 1;
      }
     }
    else if(!_stricmp("csrss.exe", processname))
     {
     if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"Video") &&
      (ObjectAttributes->ObjectName->Length == 28))
      {
      PDRIVER_DEVICE_EXTENSION dx;
      WCHAR DevNumber = ObjectAttributes->ObjectName->Buffer[13];
      BYTE iDevNumber = (BYTE)DevNumber;
      iDevNumber -= 0x30;

      #if DBG
       DbgPrint("M: iDevNumber %X\n", iDevNumber);
      #endif
      dx = GetDx();
      if (dx && (iDevNumber < 10))
       {
       if (!dx->HaveAllConsoleDevices) //если в наличии все устройства для консольной сессии
        {
        ULONG WorkStationNumber = dx->StartSettings->Video[iDevNumber];
        if (WorkStationNumber > 0)
         {
         if (dx->Sessions[WorkStationNumber - 1] != PsGetCurrentProcessSessionId())
          {
          #if DBG
           DbgPrint("M: NewNewNtOpenFile\n");
           DbgPrint("M: File Name: %wZ\n", ObjectAttributes->ObjectName);
           DbgPrint("M: Process: %s\n", processname);
           DbgPrint("M: Process Id: %d\n", PsGetCurrentProcessId());
           DbgPrint("=========================\n");
          #endif
          isTrue = 1;
          }
         }
        }

       }

      }
     }
    }
   }
  }
 if (isTrue)
  res = 0xC0000022;
 else
  res = OldNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик запроса информации о процессе
//----------------------------------------------------------------------------------------------------
 NTSTATUS NewNtQueryInformationProcess(
    IN HANDLE  ProcessHandle,
    IN PROCESSINFOCLASS  ProcessInformationClass,
    OUT PVOID  ProcessInformation,
    IN ULONG  ProcessInformationLength,
    OUT PULONG  ReturnLength
 )
 {
 int isTrue = 0;
 NTSTATUS res, ret;
 PCHAR processname = GetProcessName();
 PEPROCESS ep = NULL;
 PPEB peb;
 int tmp;

 if (IsProgSession(PsGetCurrentProcessSessionId()))
  {
  if ((PsGetCurrentProcessSessionId() != 0) && (ProcessInformationClass == ProcessSessionInformation))
   {
   PDRIVER_DEVICE_EXTENSION dx = GetDx();
   if (dx)
    {
    if (strstr(dx->NullSessionProcList, "All") || strstr(dx->NullSessionProcList, processname))
     {
     #if DBG
      DbgPrint("M: NewNtQueryInformationProcess\n");
      DbgPrint("M: Process: %s\n", processname);
      DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
      DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
      DbgPrint("=========================\n");
     #endif
     isTrue = 1;
     }
    }
   }
  }

 res = OldNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

 if (isTrue)
  {
  ret = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &ep);
  if(!NT_SUCCESS(ret))
   {
   #if DBG
    DbgPrint("M: PsLookupProcessByProcessId failed %X\n", ret);
   #endif
   }
  else
   {
   peb = PsGetProcessPeb(ep);
   #if DBG
    DbgPrint("PEB: %X\n", peb);
    DbgPrint("PEB: %X\n", ((BYTE *)((BYTE *)peb + 0x1D4)));
    DbgPrint("PEB Session ID: %X\n", *((int *)((BYTE *)peb + 0x1D4)));
   #endif
   *((int *)((BYTE *)peb + 0x1D4)) = 0;
   }
  *((ULONG *)ProcessInformation) = 0;
  }

 return res;
}

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик запроса информации о ните
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtQueryInformationToken(
     IN HANDLE  TokenHandle,
     IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
     OUT PVOID  TokenInformation,
     IN ULONG  TokenInformationLength,
     OUT PULONG  ReturnLength
 )
 {
 int isTrue = 0;
 NTSTATUS res;
 PCHAR processname = GetProcessName();

 if ((PsGetCurrentProcessSessionId() != 0) && IsProgSession(PsGetCurrentProcessSessionId()))
  {
  if (TokenInformationClass == TokenSessionId)
   {
   PDRIVER_DEVICE_EXTENSION dx = GetDx();
   if (dx)
    {
    if (strstr(dx->NullSessionProcList, "All") || strstr(dx->NullSessionProcList, processname))
     {
     #if DBG
      DbgPrint("M: NewNtQueryInformationToken\n");
      DbgPrint("M: Process: %s\n", processname);
      DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
      DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
      DbgPrint("=========================\n");
     #endif
     isTrue = 1;
     }
    }
   }
  }

 res = OldNtQueryInformationToken(TokenHandle, TokenInformationClass, TokenInformation,
  TokenInformationLength, ReturnLength);

 if (isTrue)
  {
  *((ULONG *)TokenInformation) = 0;
  }

return res;
}

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtSetSystemInformation(
     IN SYSTEM_INFORMATION_CLASS  SystemInformationClass,
     IN PSYSTEM_GDI_DRIVER_INFORMATION  SystemInformation,
     IN ULONG  SystemInformationLength
 )
 {
 int isCreateSession = 0;
 ULONG i;
 NTSTATUS res;
 PCHAR processname = GetProcessName();
 SYSTEM_GDI_DRIVER_INFORMATION NewDrvInfo;
 PDRIVER_DEVICE_EXTENSION dx;

 if (!_stricmp("smss.exe", processname))
  {
  if (SystemInformationClass == SystemCreateSession)
   {
   PDEVICE_OBJECT fdo;
   DbgPrint("M: NewNtSetSystemInformation SystemCreateSession\n");
   dx = GetDx();
   if (dx)
    {
    if (dx->InSessionStart)
     {
     #if DBG
      DbgPrint("M: Process: %s\n", processname);
      DbgPrint("M: SystemInformationLength: %x\n", SystemInformationLength);
      DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
      DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
      DbgPrint("=========================\n");
     #endif

     isCreateSession = 1;
     }
    }
   }
  }
 else if (SystemInformationClass == SystemLoadImage)
  {
  if (!_stricmp("csrss.exe", processname))
   {
   if (MyStrUnicodeString(&SystemInformation->DriverName, L"ati2dvag.dll"))
    {
    #if DBG
     DbgPrint("M: NewNtSetSystemInformation\n");
     DbgPrint("M: Process: %s\n", processname);
     DbgPrint("M: SystemInformationLength: %x\n", SystemInformationLength);
     DbgPrint("M: ModuleName: %wZ\n", &SystemInformation->DriverName.Buffer);
     DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
     DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
     DbgPrint("=========================\n");
    #endif

    RtlInitUnicodeString(&NewDrvInfo.DriverName, L"\\SystemRoot\\System32\\ati3duag.dll");
    res = OldNtSetSystemInformation(SystemLoadImage, &NewDrvInfo, sizeof(SYSTEM_GDI_DRIVER_INFORMATION));

    #if DBG
     DbgPrint("M: res: %X\n", res);
     DbgPrint("=========================\n");
    #endif
    }
   }
  }

 res = OldNtSetSystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength);
 if (isCreateSession)
  {
  #if DBG
   DbgPrint("M: res: %X\n", res);
   DbgPrint("=========================\n");
  #endif
  }

 if (isCreateSession && (res == STATUS_SUCCESS))
  {
  #if DBG
   DbgPrint("M: SessionId: %X\n", *((ULONG *)SystemInformation));
   DbgPrint("=========================\n");
  #endif
  dx->LastWorkstation ++;
  dx->Sessions[dx->LastWorkstation] = *((ULONG *)SystemInformation);
  }

 return res;
}

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик создания порта
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtCreatePort(
    OUT PHANDLE  PortHandle,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    IN ULONG  MaxConnectInfoLength,
    IN ULONG  MaxDataLength,
    IN OUT PULONG  Reserved OPTIONAL
 )
 {
 int isTrue = 0;
 NTSTATUS res;

 if (IsProgSession(PsGetCurrentProcessSessionId()))
  {
  PCHAR processname = GetProcessName();
  if ((PsGetCurrentProcessSessionId() != 0) && !_stricmp("winlogon.exe", processname))
   {
   if (ObjectAttributes)
    {
    if (ObjectAttributes->ObjectName)
     {
     if (!MyCompareUnicodeStringI(ObjectAttributes->ObjectName, L"\\Security\\WxApiPort"))
      {
      #if DBG
       DbgPrint("M: NewNtCreatePort\n");
       DbgPrint("M: Port Name: %wZ\n", ObjectAttributes->ObjectName);
       DbgPrint("M: Process: %s\n", processname);
       DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
       DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
       DbgPrint("=========================\n");
      #endif
      isTrue = 1;
      }
     }
    }
   }
  }

 if (isTrue)
  {
  res = 0xC0000035;
  }
 else
  {
  res = OldNtCreatePort(PortHandle, ObjectAttributes, MaxConnectInfoLength, MaxDataLength, Reserved);
  }

 return res;
}

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик создания файла
//----------------------------------------------------------------------------------------------------
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
 )
 {
 int isTrue = 0;
 ULONG i;
 NTSTATUS res, status;
 if (IsProgSession(PsGetCurrentProcessSessionId()))
  {
  PCHAR processname = GetProcessName();

  if (ObjectAttributes)
   {
   if (ObjectAttributes->ObjectName)
    {
    if (ObjectAttributes->ObjectName->Buffer && (ObjectAttributes->ObjectName->Length > 0))
     {
     if (!_stricmp("csrss.exe", processname))
      {
      if (PsGetCurrentProcessSessionId()) //для ненулевых сессий
       {
       if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"PointerClass0"))
        {
        PDRIVER_DEVICE_EXTENSION dx = GetDx();
        #if DBG
         DbgPrint("M: in PointerClass0\n");
        #endif
        if (dx)
         {
         if (!dx->HaveAllConsoleDevices) //если в наличии все устройства для консольной сессии
          {
          UNICODE_STRING NewName;
          ULONG ThisWorkStation = GetWorkStationNumber(dx);
          #if DBG
           DbgPrint("M: in ThisWorkStation %X\n", ThisWorkStation);
          #endif
          ObjectAttributes->ObjectName = NULL;
          for (i = 0; i < 10; i ++)
           {
           if (dx->StartSettings->Pointers[i] == ThisWorkStation)
            {
            WCHAR wcDeviceName[32];
            swprintf(wcDeviceName, L"\\Device\\PointerClass%d", i);
            RtlInitUnicodeString(&NewName, wcDeviceName);
            ObjectAttributes->ObjectName = &NewName;
            #if DBG
             DbgPrint("M: in NewName %ws\n", ObjectAttributes->ObjectName->Buffer);
            #endif
            break;
            }
           }
          }
         }
        }
       else if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"KeyboardClass0"))
        {
        PDRIVER_DEVICE_EXTENSION dx = GetDx();
        #if DBG
         DbgPrint("M: in KeyboardClass0\n");
        #endif
        if (dx)
         {
         if (!dx->HaveAllConsoleDevices) //если в наличии все устройства для консольной сессии
          {
          UNICODE_STRING NewName;
          ULONG ThisWorkStation = GetWorkStationNumber(dx);
          #if DBG
           DbgPrint("M: in ThisWorkStation %X\n", ThisWorkStation);
          #endif
          ObjectAttributes->ObjectName = NULL;
          for (i = 0; i < 10; i ++)
           {
           if (dx->StartSettings->Keyboards[i] == ThisWorkStation)
            {
            WCHAR wcDeviceName[32];
            swprintf(wcDeviceName, L"\\Device\\KeyboardClass%d", i);
            RtlInitUnicodeString(&NewName, wcDeviceName);
            ObjectAttributes->ObjectName = &NewName;
            #if DBG
             DbgPrint("M: in NewName %ws\n", ObjectAttributes->ObjectName->Buffer);
            #endif
            break;
            }
           }
          }
         }
        }
       }
      else //для нулевой сессии
       {
       if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"\\??\\") ||
        MyStrUnicodeString(ObjectAttributes->ObjectName, L"\\??\\"))
        {
        PDRIVER_DEVICE_EXTENSION dx = GetDx();
        if (dx)
         {
         if (!dx->HaveAllConsoleDevices) //если в наличии все устройства для консольной сессии
          {
          HANDLE LinkHandle;
          OBJECT_ATTRIBUTES LinkAttributes;
          IO_STATUS_BLOCK IO;
          InitializeObjectAttributes(&LinkAttributes, ObjectAttributes->ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);
          status = ZwOpenFile(&LinkHandle, FILE_READ_DATA, &LinkAttributes, &IO, FILE_SHARE_READ, 0);
          #if DBG
           DbgPrint("M: NtOpenFile: %X\n", status);
          #endif
          if (status == STATUS_SUCCESS)
           {
           PFILE_OBJECT FileObject;
           PDEVICE_OBJECT DeviceObject;
           status = ObReferenceObjectByHandle(LinkHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode,
            (PVOID *)&FileObject, NULL);
           #if DBG
            DbgPrint("M: ObReferenceObjectByHandle: %X\n", status);
           #endif
           DeviceObject = FileObject->DeviceObject;
           #if DBG
            DbgPrint("M: DeviceObject: %X\n", DeviceObject);
           #endif
           for (i = 0; i < 10; i ++)
            {
            //
            #if DBG
             DbgPrint("M: dx->KeyboardsPDO[%d]: %X\n", i, dx->KeyboardsPDO[i]);
             DbgPrint("M: dx->StartSettings->Keyboards[%d]: %X\n", i, dx->StartSettings->Keyboards[i]);
            #endif
            //

            if (dx->KeyboardsPDO[i] == DeviceObject)
             {
             if (dx->StartSettings->Keyboards[i] != 1)
              isTrue = TRUE;
             break;
             }
            if (dx->PointersPDO[i] == DeviceObject)
             {
             if (dx->StartSettings->Pointers[i] != 1)
              isTrue = TRUE;
             break;
             }
            }
           ObDereferenceObject(FileObject);
           ZwClose(LinkHandle);
           }
          #if DBG
           DbgPrint("M: NewNtCreateFile\n");
           DbgPrint("M: File Name: %wZ\n", ObjectAttributes->ObjectName);
           DbgPrint("M: Process: %s\n", processname);
           DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
           DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
           DbgPrint("M: isTrue: %d\n",  isTrue);
           DbgPrint("=========================\n");
          #endif
          }
         }
        }

       }
      }

     else if (MyStrUnicodeString(ObjectAttributes->ObjectName, L"\\Device\\00") ||
      MyStrUnicodeString(ObjectAttributes->ObjectName, L"\\??\\HID") ||
      MyStrUnicodeString(ObjectAttributes->ObjectName, L"\\??\\hid") ) //пытаются открыть HID - устройство
      {
      PDRIVER_DEVICE_EXTENSION dx = GetDx();
      if (dx)
       {
       HANDLE LinkHandle;
       OBJECT_ATTRIBUTES LinkAttributes;
       IO_STATUS_BLOCK IO;
       InitializeObjectAttributes(&LinkAttributes, ObjectAttributes->ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);
       status = ZwOpenFile(&LinkHandle, FILE_READ_DATA, &LinkAttributes, &IO, FILE_SHARE_READ, 0);
       #if DBG
        DbgPrint("M: NtOpenFile: %X\n", status);
       #endif
       if (status == STATUS_SUCCESS)
        {
        PFILE_OBJECT FileObject;
        PDEVICE_OBJECT DeviceObject;
        status = ObReferenceObjectByHandle(LinkHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode,
         (PVOID *)&FileObject, NULL);
        #if DBG
         DbgPrint("M: ObReferenceObjectByHandle: %X\n", status);
        #endif
        DeviceObject = FileObject->DeviceObject;
        #if DBG
         DbgPrint("M: DeviceObject: %X\n", DeviceObject);
        #endif

        if (DeviceObject)
         {
         DeviceObject = IoGetDeviceAttachmentBaseRef(DeviceObject);
         #if DBG
          DbgPrint("M: IoGetDeviceAttachmentBaseRef DeviceObject: %X\n", DeviceObject);
         #endif
         if (DeviceObject)
          {
          for (i = 0; i < 10; i ++)
           {
           if (dx->HidsPDO[i] == DeviceObject)
            {
            ULONG ThisWorkStation = GetWorkStationNumber(dx) - 1;

            #if DBG
             DbgPrint("M: NewNtCreateFile\n");
             DbgPrint("M: Mask: %X\n",  dx->StartSettings->Hids[i].Mask);
            #endif

            if (!ThisWorkStation) //если 0
             isTrue = !(dx->StartSettings->Hids[i].Mask & 1);
            else
             isTrue = !(dx->StartSettings->Hids[i].Mask & (2 << (ThisWorkStation - 1)));

            break;
            }
           }

          }
         }

        ObDereferenceObject(FileObject);
        ZwClose(LinkHandle);
        }

       }

      #if DBG
       DbgPrint("M: NewNtCreateFile\n");
       DbgPrint("M: File Name: %wZ\n", ObjectAttributes->ObjectName);
       DbgPrint("M: Process: %s\n", processname);
       DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
       DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
       DbgPrint("M: isTrue: %d\n",  isTrue);
       DbgPrint("=========================\n");
      #endif

      }

     }
    }
   }
  }

 if (isTrue)
  res = 0xC0000034;
 else
  res = OldNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
   ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик запроса значения ключа реестра
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtQueryValueKey(
     IN HANDLE  KeyHandle,
     IN PUNICODE_STRING  ValueName,
     IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
     OUT PMY_KEY_VALUE_PARTIAL_INFORMATION  KeyValueInformation,
     IN ULONG  Length,
     OUT PULONG  ResultLength
 )
 {
 NTSTATUS res, status;
 BOOLEAN isTrue = FALSE;

 if (ValueName)
  {
  if (ValueName->Buffer && (ValueName->Length > 0))
   {
   PCHAR processname = GetProcessName();
   BYTE TmpBuffer[1024];
   ULONG DW;
   POBJECT_NAME_INFORMATION ObjectNameInfo = (POBJECT_NAME_INFORMATION)TmpBuffer;

   //Используем для каждого рабочего места свой логин, пароль и автовход
   if (_stricmp(UTIL_NAME, processname) && (!MyCompareUnicodeStringI(ValueName, L"DefaultUserName") || !MyCompareUnicodeStringI(ValueName, L"DefaultDomainName") ||
     !MyCompareUnicodeStringI(ValueName, L"DefaultPassword") || !MyCompareUnicodeStringI(ValueName, L"AutoAdminLogon")))
    {
    PDRIVER_DEVICE_EXTENSION dx = GetDx();
    if (dx)
     {
     if (!MyCompareUnicodeStringI(ValueName, L"AutoAdminLogon") && (GetWorkStationNumber(dx) > 0) &&
      dx->CanContinueShutdown && (dx->CanContinueAnswers[GetWorkStationNumber(dx) - 1] == 1)) //если все согласились выйти, то не будем больше входить
      {
      res = 0xC0000022;
      isTrue = TRUE;
      }
     else if ((PsGetCurrentProcessSessionId() != 0) && IsProgSession(PsGetCurrentProcessSessionId()))
      {
      PFILE_OBJECT KeyFile;
      status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
       (PVOID *)&KeyFile, NULL);
      #if DBG
       DbgPrint("M: DefUser ObReferenceObjectByHandle: %X\n", status);
      #endif
      if (status == STATUS_SUCCESS)
       {
       status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
       #if DBG
        DbgPrint("M: DefUser ObQueryNameString: %X\n", status);
       #endif
       ObDereferenceObject(KeyFile);
       if (status == STATUS_SUCCESS)
        {
        #if DBG
         DbgPrint("M: DefUser ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
        #endif
        if (!MyCompareUnicodeStringI(&ObjectNameInfo->Name, L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON"))
         {
         WCHAR wcParamName[32];
         UNICODE_STRING NewName;

         swprintf(wcParamName, L"%ws_%d", ValueName->Buffer, GetWorkStationNumber(dx));

         RtlInitUnicodeString(&NewName, wcParamName);

         res = ZwQueryValueKey(KeyHandle, &NewName, KeyValueInformationClass, KeyValueInformation, Length,
          ResultLength);

         ValueName = &NewName;

         #if DBG
          DbgPrint("M: NewNtQueryValueKey\n");
          DbgPrint("M: ValueName: %wZ\n", ValueName);
          DbgPrint("M: Process: %s\n", processname);
          DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
          DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
          DbgPrint("=========================\n");
         #endif
         isTrue = TRUE;
         }
        }
       }
      }
     }
    }
   else if (!MyCompareUnicodeStringI(ValueName, L"AllowMultipleTSSessions"))
    {
    PDRIVER_DEVICE_EXTENSION dx = GetDx();
    if (dx && !dx->EnableMultipleTSSessions)
     {
     PFILE_OBJECT KeyFile;
     status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
      (PVOID *)&KeyFile, NULL);
     #if DBG
      DbgPrint("M: DefUser ObReferenceObjectByHandle: %X\n", status);
     #endif
     if (status == STATUS_SUCCESS)
      {
      status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
      #if DBG
       DbgPrint("M: DefUser ObQueryNameString: %X\n", status);
      #endif
      ObDereferenceObject(KeyFile);
      if (status == STATUS_SUCCESS)
       {
       #if DBG
        DbgPrint("M: DefUser ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
       #endif
       if (!MyCompareUnicodeStringI(&ObjectNameInfo->Name, L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON"))
        {
        *((ULONG*)KeyValueInformation->Data) = 0;
        res = 0;
        KeyValueInformation->DataLength = 4;
        KeyValueInformation->Type = REG_DWORD;
        isTrue = TRUE;
        }
       }
      }
     }
    }
   else if (!MyCompareUnicodeStringI(ValueName, L"Policies"))
    {
    if (IsProgSession(PsGetCurrentProcessSessionId()))
     {
     PFILE_OBJECT KeyFile;
     status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
      (PVOID *)&KeyFile, NULL);
     #if DBG
      DbgPrint("M: ObReferenceObjectByHandle: %X\n", status);
     #endif
     if (status == STATUS_SUCCESS)
      {
      status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
      #if DBG
       DbgPrint("M: ObQueryNameString: %X\n", status);
      #endif
      ObDereferenceObject(KeyFile);
      if (status == STATUS_SUCCESS)
       {
       #if DBG
        DbgPrint("M: ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
       #endif

       if (MyStrUnicodeString(&ObjectNameInfo->Name, L"\\PowerCfg\\PowerPolicies"))
        {
        res = OldNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length,
         ResultLength);

        #if DBG
         DbgPrint("M: NewNtQueryValueKey\n");
         DbgPrint("M: ValueName: %wZ\n", ValueName);
         DbgPrint("M: Process: %s\n", processname);
         DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
         DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
         DbgPrint("=========================\n");
        #endif
        isTrue = TRUE;

        if (*ResultLength > 0x48)
         {
         ULONG VideoTimeoutAc = *((ULONG *)KeyValueInformation + 0x11);
         ULONG VideoTimeoutDc = *((ULONG *)KeyValueInformation + 0x12);
         #if DBG
          DbgPrint("M: Old VideoTimeoutAc %X\n", VideoTimeoutAc);
          DbgPrint("M: Old VideoTimeoutDc %X\n", VideoTimeoutDc);
         #endif

         *((ULONG *)KeyValueInformation + 0x11) = 0;
         *((ULONG *)KeyValueInformation + 0x12) = 0;

         }
        }
       }
      }
     }

    }

   else if (!MyCompareUnicodeStringI(ValueName, DEMO_REG_STARTUP_COUNT))
    {
    #if DEMO
    if (_stricmp("System", processname) && _stricmp(UTIL_NAME, processname) && _stricmp("smss.exe", processname))
     {
    #else
    if (_stricmp("System", processname) || _stricmp(UTIL_NAME, processname) || _stricmp("smss.exe", processname))
     {
    #endif
     PFILE_OBJECT KeyFile;
     status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
      (PVOID *)&KeyFile, NULL);
     #if DBG
      DbgPrint("M: Attach.ToDesktop ObReferenceObjectByHandle: %X\n", status);
     #endif
     if (status == STATUS_SUCCESS)
      {
      status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
      #if DBG
       DbgPrint("M: Attach.ToDesktop ObQueryNameString: %X\n", status);
      #endif
      ObDereferenceObject(KeyFile);
      if (status == STATUS_SUCCESS)
       {
       #if DBG
        DbgPrint("M: Attach.ToDesktop ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
       #endif
       //не перехватываем обращения к SYSTEM\\CurrentControlSet\\Hardware Profiles\\
       //перехватываем только наш бред
       if (!MyStrUnicodeString(&ObjectNameInfo->Name, L"\\Hardware Profiles\\"))
        {
        *((ULONG*)KeyValueInformation->Data) = 0;
        res = 0;
        KeyValueInformation->DataLength = 4;
        KeyValueInformation->Type = REG_DWORD;
        isTrue = TRUE;
        }
       }
      }
     }

    }

   }
  }

 if (isTrue)
  {
  DbgPrint("M: res: %X\n", res);
  DbgPrint("=========================\n");
  }
 else
  res = OldNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length,
   ResultLength);

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик запроса сохранения ключа реестра
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtSetValueKey(
     IN HANDLE  KeyHandle,
     IN PUNICODE_STRING  ValueName,
     IN ULONG  TitleIndex OPTIONAL,
     IN ULONG  Type,
     IN PVOID  Data,
     IN ULONG  DataSize
 )
 {
 NTSTATUS res, status;
 BOOLEAN isTrue = FALSE;

 if (ValueName)
  {
  if (ValueName->Buffer && (ValueName->Length > 0))
   {
   PCHAR processname = GetProcessName();
   BYTE TmpBuffer[1024];
   ULONG DW;
   POBJECT_NAME_INFORMATION ObjectNameInfo = (POBJECT_NAME_INFORMATION)TmpBuffer;

   if (_stricmp(UTIL_NAME, processname) && (!MyCompareUnicodeStringI(ValueName, L"DefaultUserName") ||
    !MyCompareUnicodeStringI(ValueName, L"DefaultDomainName") || !MyCompareUnicodeStringI(ValueName, L"DefaultPassword") ||
    !MyCompareUnicodeStringI(ValueName, L"AutoAdminLogon")))
    {
    if ((PsGetCurrentProcessSessionId() != 0) && IsProgSession(PsGetCurrentProcessSessionId()))
     {
     PFILE_OBJECT KeyFile;
     status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
      (PVOID *)&KeyFile, NULL);
     #if DBG
      DbgPrint("M: DefUser ObReferenceObjectByHandle: %X\n", status);
     #endif
     if (status == STATUS_SUCCESS)
      {
      status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
      #if DBG
       DbgPrint("M: DefUser ObQueryNameString: %X\n", status);
      #endif
      ObDereferenceObject(KeyFile);
      if (status == STATUS_SUCCESS)
       {
       #if DBG
        DbgPrint("M: DefUser ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
       #endif
       if (!MyCompareUnicodeStringI(&ObjectNameInfo->Name, L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON"))
        {
        PDRIVER_DEVICE_EXTENSION dx = GetDx();
        if (dx)
         {
         WCHAR wcParamName[32];
         UNICODE_STRING NewName;
         swprintf(wcParamName, L"%ws_%d", ValueName->Buffer, GetWorkStationNumber(dx));

         RtlInitUnicodeString(&NewName, wcParamName);

         res = ZwSetValueKey(KeyHandle, &NewName, TitleIndex, Type, Data, DataSize);

         ValueName = &NewName;

         #if DBG
          DbgPrint("M: NewNtSetValueKey\n");
          DbgPrint("M: ValueName: %wZ\n", ValueName);
          DbgPrint("M: Process: %s\n", processname);
          DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
          DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
          DbgPrint("=========================\n");
         #endif

         isTrue = TRUE;
         }
        }
       }
      }
     }
    }

   else if (!MyCompareUnicodeStringI(ValueName, L"AllowMultipleTSSessions"))
    {
    PDRIVER_DEVICE_EXTENSION dx = GetDx();
    if (dx && !dx->EnableMultipleTSSessions)
     {
     PFILE_OBJECT KeyFile;
     status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
      (PVOID *)&KeyFile, NULL);
     #if DBG
      DbgPrint("M: DefUser ObReferenceObjectByHandle: %X\n", status);
     #endif
     if (status == STATUS_SUCCESS)
      {
      status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
      #if DBG
       DbgPrint("M: DefUser ObQueryNameString: %X\n", status);
      #endif
      ObDereferenceObject(KeyFile);
      if (status == STATUS_SUCCESS)
       {
       #if DBG
        DbgPrint("M: AllowMultipleTSSessions ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
       #endif
       if (!MyCompareUnicodeStringI(&ObjectNameInfo->Name, L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON"))
        {
        res = 0;
        isTrue = TRUE;
        }
       }
      }
     }

    }

   else if (!MyCompareUnicodeStringI(ValueName, DEMO_REG_STARTUP_COUNT))
    {
    if (_stricmp("System", processname) && _stricmp(UTIL_NAME, processname) && _stricmp("smss.exe", processname))
     {
     PFILE_OBJECT KeyFile;
     status = ObReferenceObjectByHandle(KeyHandle, FILE_ALL_ACCESS, NULL, KernelMode,
      (PVOID *)&KeyFile, NULL);
     #if DBG
      DbgPrint("M: Attach.ToDesktop ObReferenceObjectByHandle: %X\n", status);
     #endif
     if (status == STATUS_SUCCESS)
      {
      status = ObQueryNameString(KeyFile, ObjectNameInfo, 1024, &DW);
      #if DBG
       DbgPrint("M: Attach.ToDesktop ObQueryNameString: %X\n", status);
      #endif
      ObDereferenceObject(KeyFile);
      if (status == STATUS_SUCCESS)
       {
       #if DBG
        DbgPrint("M: Attach.ToDesktop ObQueryNameString: %wZ\n", &ObjectNameInfo->Name);
       #endif
       //не перехватываем обращения к SYSTEM\\CurrentControlSet\\Hardware Profiles\\
       //перехватываем только наш бред
       if (!MyStrUnicodeString(&ObjectNameInfo->Name, L"\\Hardware Profiles\\"))
        {
        res = 0;
        isTrue = TRUE;
        }
       }
      }
     }
    }

   }
  }

 if (isTrue)
  {
  DbgPrint("M: res: %X\n", res);
  DbgPrint("=========================\n");
  }
 else
  res = OldNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция-перехватчик чтения из LPC
//----------------------------------------------------------------------------------------------------
NTSTATUS NewNtRequestWaitReplyPort(
     IN HANDLE  PortHandle,
     IN PCSR_API_MESSAGE  Request,
     OUT PCSR_API_MESSAGE  IncomingReply
 )
 {
 NTSTATUS res, status;
 BOOLEAN isTrue = FALSE;

 if (IsProgSession(PsGetCurrentProcessSessionId()))
  {
  PCHAR processname = GetProcessName();
  if (!_stricmp("winlogon.exe", processname))
   {
   if (PortHandle == WinlogonApiPort)
    {
    ULONG ApiNumber = *((ULONG *)((BYTE*)Request+0x1C));
    ULONG ExitFlag  = *((ULONG *)((BYTE*)Request+0x2C));
    ULONG AdvParam  = *((ULONG *)((BYTE*)Request+0x34));

    if ((ApiNumber == 0x30400) && ExitFlag && AdvParam)
     {
     ULONG CanShutdownRes = CanShutdown();
     /*for (int i = 0; i < (0x38 / 4); i ++)
      DbgPrint("M: %X\n", *((ULONG*)Request+i));*/

     #if DBG
      DbgPrint("M: NewNtRequestWaitReplyPort\n");
      DbgPrint("M: ApiNumber: %X\n", ApiNumber);
      DbgPrint("M: ExitFlag: %X\n", ExitFlag);
      DbgPrint("M: AdvParam: %X\n", AdvParam);
      DbgPrint("M: Process: %s\n", processname);
      DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
      DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
      DbgPrint("=========================\n");
     #endif

     if (CanShutdownRes == 0) //если все разрешили завершение работы
      {
      DbgPrint("M: CanShutdown\n");
      }
     else
      {
      if (CanShutdownRes == 1) //если инициатор отменил, то ничего не делаем
       {
       isTrue = TRUE;
       }
      else //если отменил кто-то другой вылогиневываем инициатора
       {
       DbgPrint("M: Can'tShutdown\n");
       *((ULONG *)((BYTE*)Request+0x2C)) = 0;
       *((ULONG *)((BYTE*)Request+0x34)) = 0;
       }
      }
     }
    }
   }
  }

 if (isTrue)
  res = 0x0;
 else
  res = OldNtRequestWaitReplyPort(PortHandle, (PLPC_MESSAGE)Request, (PLPC_MESSAGE)IncomingReply);

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция
//----------------------------------------------------------------------------------------------------
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
 )
 {
 NTSTATUS res, status;
 BOOLEAN isTrue = FALSE;

 if (IsProgSession(PsGetCurrentProcessSessionId()))
  {
  PCHAR processname = GetProcessName();
  if (!_stricmp("winlogon.exe", processname))
   {
   if (PortName)
    {
    if (PortName->Buffer && PortName->Length)
     {
     if (MyStrUnicodeString(PortName, L"\\ApiPort"))
      {
      #if DBG
       DbgPrint("M: NewNtSecureConnectPort\n");
       DbgPrint("M: Port Name: %wZ\n", PortName);
       DbgPrint("M: Process: %s\n", processname);
       DbgPrint("M: Process Id: %d\n",  PsGetCurrentProcessId());
       DbgPrint("M: Session Id: %d\n",  PsGetCurrentProcessSessionId());
       DbgPrint("=========================\n");
      #endif
      isTrue = TRUE;
      }
     }
    }
   }
  }

 res = OldNtSecureConnectPort(ConnectedPort, PortName, Qos, WriteMap, ServerSid, ReadMap, MaxMessageSize, ConnectInfo, UserConnectInfoLength);

 if (isTrue)
  {
  WinlogonApiPort = *ConnectedPort;
  #if DBG
   DbgPrint("M: WinlogonApiPort: %X\n", WinlogonApiPort);
   DbgPrint("=========================\n");
  #endif
  }

 return res;
 }