//---------------------------------------------------------------------------
// Клавиатурно-мышиный фильтр для подсветки текущего устройства
//---------------------------------------------------------------------------
#include "driver.h"
#include "stdio.h"

// Предварительное объявление функций:
NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp );
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);

NTSTATUS MyPassThru(PDEVICE_OBJECT fdo, PIRP theIRP);
NTSTATUS DispatchPower(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp);

VOID __stdcall StartReadFromInput(PKBDDRIVER_DEVICE_EXTENSION dx);
VOID __stdcall ReadFromInput(PREAD_THREAD_DATA rd);

// Константы
#define DEVICE L"WMDEVICE"

#define SYM_LINK_NAME L"\\DosDevices\\KbdHook"
#define DEVICE_NAME L"\\Device\\KBDHOOK"

#pragma code_seg("INIT") // начало секции INIT

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
 {
 NTSTATUS status = STATUS_SUCCESS;
 UNICODE_STRING devName;
 ULONG i;
 WCHAR Buffer[32];
 UNICODE_STRING symLinkName;
 PDEVICE_OBJECT fdo = NULL;
 PKBDDRIVER_DEVICE_EXTENSION dx = NULL;
 PDRIVER_DEVICE_EXTENSION MainDx = NULL;

 #if DBG
  DbgPrint("K: In DriverEntry\n");
  DbgPrint("K: RegistryPath = %wZ\n", RegistryPath);
 #endif

 for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
  DriverObject->MajorFunction[i] = MyPassThru;
 DriverObject->DriverUnload = UnloadRoutine;
 DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]= DeviceControlRoutine;
 DriverObject->MajorFunction[IRP_MJ_POWER]= DispatchPower;

 RtlInitUnicodeString(&devName, DEVICE_NAME);
 status = IoCreateDevice(DriverObject, sizeof(KBDDRIVER_DEVICE_EXTENSION), &devName,
  FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);

 if (! NT_SUCCESS(status))
  return status;

 dx = (PKBDDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
 dx->fdo = fdo;  // Обратный указатель
 #if DBG
  DbgPrint("K: FDO %X, DevExt=%X\n", fdo, dx);
 #endif

 // Формируем символьное имя
 wcscpy(dx->SymLinkNameBuf, SYM_LINK_NAME);
 RtlInitUnicodeString( &symLinkName, dx->SymLinkNameBuf);
 dx->SymLinkName = symLinkName;
 dx->IsInputDevice = FALSE;
 dx->LastDeviceNumber = -1;
 dx->LastIsKeyboard = -1;
 dx->FreeInputDeviceCount = 0;
 dx->StopReadFreeInput = FALSE;

 // Создаем символьную ссылку
 status = IoCreateSymbolicLink( &symLinkName, &devName );
 if (!NT_SUCCESS(status))
  {
  IoDeleteDevice(fdo);
  return status;
  }

 for (i = 0; i < 10; i++)
  {
  PDEVICE_OBJECT pCurDevice = NULL;
  swprintf(Buffer, L"KeyboardClass%d", i);
  SearchDevice(&pCurDevice, Buffer);
  #if DBG
   DbgPrint("K: Buffer %ws\n", Buffer);
  #endif
  if (pCurDevice)
   {
   PDEVICE_OBJECT HookDevice = NULL;
   PKBDDRIVER_DEVICE_EXTENSION InputDx = NULL;
   swprintf(Buffer, L"\\Device\\KeyboardClassHook%d", i);
   RtlInitUnicodeString( &devName, Buffer);
   status = IoCreateDevice(DriverObject, sizeof(KBDDRIVER_DEVICE_EXTENSION), &devName,
    FILE_DEVICE_KEYBOARD, 0, FALSE, &HookDevice);
   if(!NT_SUCCESS(status))
    return status;

   InputDx = (PKBDDRIVER_DEVICE_EXTENSION)HookDevice->DeviceExtension;
   InputDx->fdo = HookDevice;  // Обратный указатель
   InputDx->IsInputDevice = TRUE;
   InputDx->InputDevice = pCurDevice;
   InputDx->InputDeviceNumber = i;
   InputDx->MainFdo = fdo;
   InputDx->IsKeybord = TRUE;

   HookDevice->Flags = HookDevice->Flags
    | (DO_BUFFERED_IO | DO_POWER_PAGABLE);
   HookDevice->Flags = HookDevice->Flags &
    ~DO_DEVICE_INITIALIZING;

   IoAttachDeviceToDeviceStack(HookDevice, pCurDevice);
   }
  }

 for (i = 0; i < 10; i++)
  {
  PDEVICE_OBJECT pCurDevice = NULL;
  swprintf(Buffer, L"PointerClass%d", i);
  SearchDevice(&pCurDevice, Buffer);
  #if DBG
   DbgPrint("K: Buffer %ws\n", Buffer);
  #endif
  if (pCurDevice)
   {
   PDEVICE_OBJECT HookDevice = NULL;
   PKBDDRIVER_DEVICE_EXTENSION InputDx = NULL;
   swprintf(Buffer, L"\\Device\\PointerClassHook%d", i);
   RtlInitUnicodeString( &devName, Buffer);
   status = IoCreateDevice(DriverObject, sizeof(KBDDRIVER_DEVICE_EXTENSION), &devName,
    FILE_DEVICE_KEYBOARD, 0, FALSE, &HookDevice);
   if(!NT_SUCCESS(status))
    return status;

   InputDx = (PKBDDRIVER_DEVICE_EXTENSION)HookDevice->DeviceExtension;
   InputDx->fdo = HookDevice;  // Обратный указатель
   InputDx->IsInputDevice = TRUE;
   InputDx->InputDevice = pCurDevice;
   InputDx->InputDeviceNumber = i;
   InputDx->MainFdo = fdo;
   InputDx->IsKeybord = FALSE;

   HookDevice->Flags = HookDevice->Flags
    | (DO_BUFFERED_IO | DO_POWER_PAGABLE);
   HookDevice->Flags = HookDevice->Flags &
    ~DO_DEVICE_INITIALIZING;

   IoAttachDeviceToDeviceStack(HookDevice, pCurDevice);
   }
  }

  MainDx = GetDx();
  if (MainDx)
   {
   if (MainDx->StartOnBoot) //сервис стартовал при загрузке и не все устройства ввода активны
    {
    HANDLE thread_handle = NULL;
    NTSTATUS res = PsCreateSystemThread(&thread_handle, 0, NULL, 0, NULL, (PKSTART_ROUTINE)StartReadFromInput, dx);
    DbgPrint("M: PsCreateSystemThread = %d\n",res);

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
     }
    }
   }

 return status;
 }

#pragma code_seg() // end INIT section

#pragma code_seg("PAGE")
//----------------------------------------------------------------------------------------------------
// Функция запускающая нити, читающие из неиспользуемых устройст ввода
//----------------------------------------------------------------------------------------------------
VOID __stdcall StartReadFromInput(PKBDDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG i;
 READ_THREAD_DATA rd;
 PDRIVER_DEVICE_EXTENSION MainDx = GetDx();

 #if DBG
  DbgPrint("!!! K: In Thread\n");
 #endif

 if (MainDx)
  {
  WCHAR Buffer[32];
  dx->FreeInputDeviceCount = 0;
  for (i = 0; i < 10; i++)
   {
   if ((MainDx->SessionsStarted && !MainDx->StartSettings->Keyboards[i]) //сессии запущены и неопределена станция для устройства
    || (!MainDx->SessionsStarted && MainDx->StartSettings->Keyboards[i] != 1)) //или сессия незапущены и устройство не принадлежит консольной сессии
    {
    PDEVICE_OBJECT pCurDevice = NULL;
    swprintf(Buffer, L"KeyboardClass%d", i);
    SearchDevice(&pCurDevice, Buffer);
    #if DBG
     DbgPrint("K: Buffer %ws\n", Buffer);
    #endif
    if (pCurDevice)
     {
     PDEVICE_OBJECT InputDevice = IoGetDeviceAttachmentBaseRef(pCurDevice);
     #if DBG
      DbgPrint("K: InputDevice %X\n", InputDevice);
      DbgPrint("K: ReferenceCount %X\n", InputDevice->ReferenceCount);
     #endif
     dx->FreeInputDevices[dx->FreeInputDeviceCount] = InputDevice;
     dx->FreeInputDeviceCount ++;
     }
    }
   }

  for (i = 0; i < 10; i++)
   {
   if ((MainDx->SessionsStarted && !MainDx->StartSettings->Pointers[i]) //сессии запущены и неопределена станция для устройства
    || (!MainDx->SessionsStarted && MainDx->StartSettings->Pointers[i] != 1)) //или сессия незапущены и устройство не принадлежит консольной сессии
    {
    PDEVICE_OBJECT pCurDevice = NULL;
    swprintf(Buffer, L"PointerClass%d", i);
    SearchDevice(&pCurDevice, Buffer);
    #if DBG
     DbgPrint("K: Buffer %ws\n", Buffer);
    #endif
    if (pCurDevice)
     {
     PDEVICE_OBJECT InputDevice = IoGetDeviceAttachmentBaseRef(pCurDevice);
     #if DBG
      DbgPrint("K: InputDevice %X\n", InputDevice);
      DbgPrint("K: ReferenceCount %X\n", InputDevice->ReferenceCount);
     #endif
     if (InputDevice->ReferenceCount == 0)
      {
      dx->FreeInputDevices[dx->FreeInputDeviceCount] = InputDevice;
      dx->FreeInputDeviceCount ++;
      }
     }
    }
   }

  }

 dx->StopReadFreeInput = FALSE;
 for (i = 0; i < dx->FreeInputDeviceCount; i++)
  {
  NTSTATUS res;
  dx->ReadThreads[i] = NULL;
  dx->rd[i].iDeviceNumber = i;
  dx->rd[i].dx = dx;
  res = PsCreateSystemThread(&dx->ReadThreads[i], 0, NULL, 0, NULL, (PKSTART_ROUTINE)ReadFromInput,
   &dx->rd[i]);
  DbgPrint("K: PsCreateSystemThread Sub = %X\n", res);
  }

 PsTerminateSystemThread(STATUS_SUCCESS);
 }
//----------------------------------------------------------------------------------------------------
// Функция нити, читающая из неиспользуемых устройст ввода
//----------------------------------------------------------------------------------------------------
VOID __stdcall ReadFromInput(PREAD_THREAD_DATA rd)
 {
 PDEVICE_OBJECT FreeInputDevice = rd->dx->FreeInputDevices[rd->iDeviceNumber];
 NTSTATUS status;
 BYTE TmpBuffer[1024];
 ULONG DW;
 POBJECT_NAME_INFORMATION ObjectNameInfo = (POBJECT_NAME_INFORMATION)TmpBuffer;

 #if DBG
  DbgPrint("!!! K: In Sub Thread\n");
 #endif

 status = ObQueryNameString(FreeInputDevice, ObjectNameInfo, 1024, &DW);
 #if DBG
  DbgPrint("K: ObQueryNameString Sub = %d\n", status);
 #endif
 if (status == STATUS_SUCCESS)
  {
  HANDLE InputHandle;
  OBJECT_ATTRIBUTES ObjectAttributes;
  IO_STATUS_BLOCK ioStatusBlock;
  InitializeObjectAttributes(&ObjectAttributes, &ObjectNameInfo->Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwCreateFile(&InputHandle, GENERIC_READ | FILE_READ_ATTRIBUTES, &ObjectAttributes, &ioStatusBlock,
   0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, 0, 0, 0);
  #if DBG
   DbgPrint("!!!K: ZwCreateFile = %X\n", status);
  #endif
  if (status == STATUS_SUCCESS)
   {
   HANDLE hEvent;
   #if DBG
    DbgPrint("K: ReferenceCount %X\n", FreeInputDevice->ReferenceCount);
   #endif
   InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

   status = ZwCreateEvent(&hEvent, STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x03, &ObjectAttributes, NotificationEvent,
    FALSE);
   #if DBG
    DbgPrint("K: ZwCreateEvent = %d\n", status);
   #endif
   if (status == STATUS_SUCCESS)
    {
    rd->dx->ReadEvent[rd->iDeviceNumber] = hEvent;
    while(! rd->dx->StopReadFreeInput)
     {
     static LARGE_INTEGER ByteOffset;
     memset(&ioStatusBlock, 0, sizeof(ioStatusBlock));
     if (FreeInputDevice->Flags & FILE_DEVICE_KEYBOARD)
      {
      KEYBOARD_INPUT_DATA KeyboardInputData;
      status = ZwReadFile(InputHandle, hEvent, NULL, NULL, &ioStatusBlock, &KeyboardInputData,
       sizeof(KEYBOARD_INPUT_DATA), &ByteOffset, NULL);
      }
     else
      {
      MOUSE_INPUT_DATA MouseInputData;
      status = ZwReadFile(InputHandle, hEvent, NULL, NULL, &ioStatusBlock, &MouseInputData,
       sizeof(MOUSE_INPUT_DATA), &ByteOffset, NULL);
      }

     #if DBG
      DbgPrint("K: ZwReadFile %X\n", status);
     #endif

     if (status == STATUS_PENDING)
      {
      status = ZwWaitForSingleObject(hEvent,TRUE, NULL);
      #if DBG
       DbgPrint("K: ZwWaitForSingleObject %X\n", status);
      #endif
      }

     }
    ZwClose(InputHandle);
    #if DBG
     DbgPrint("K: ReferenceCount %X\n", FreeInputDevice->ReferenceCount);
    #endif
    }
   ZwClose(hEvent);
   }
  }
 #if DBG
  DbgPrint("K: Stop Read Thread\n");
 #endif
 PsTerminateSystemThread(STATUS_SUCCESS);
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
//
//----------------------------------------------------------------------------------------------------
NTSTATUS MyPassThru(PDEVICE_OBJECT fdo, PIRP Irp)
 {
 PKBDDRIVER_DEVICE_EXTENSION dx = (PKBDDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
 if (dx->IsInputDevice)
  {
  NTSTATUS res;
  PKBDDRIVER_DEVICE_EXTENSION MainDx = (PKBDDRIVER_DEVICE_EXTENSION)dx->MainFdo->DeviceExtension;
  MainDx->LastDeviceNumber = dx->InputDeviceNumber;
  MainDx->LastIsKeyboard = dx->IsKeybord;
  IoSkipCurrentIrpStackLocation(Irp);
  res = IoCallDriver(dx->InputDevice, Irp);
  return res;
  }
 else
  {
  return CompleteIrp(Irp,STATUS_SUCCESS,0); // Успешное завершение
  }
 }
//----------------------------------------------------------------------------------------------------
//
//----------------------------------------------------------------------------------------------------
NTSTATUS DispatchPower(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp)
 {
 PKBDDRIVER_DEVICE_EXTENSION dx = (PKBDDRIVER_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;
 if (dx->IsInputDevice)
  {
  PoStartNextPowerIrp(Irp);
  IoSkipCurrentIrpStackLocation(Irp);
  return PoCallDriver(dx->InputDevice, Irp);
  }
 else
  {
  return CompleteIrp(Irp,STATUS_SUCCESS,0); // Успешное завершение
  }
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
 ULONG BytesTxd = 0; // Число переданных/полученных байт
 PIO_STACK_LOCATION IrpStack=IoGetCurrentIrpStackLocation(Irp);

 //Получаем указатель на расширение устройства
 PKBDDRIVER_DEVICE_EXTENSION dx = (PKBDDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;

 if (dx->IsInputDevice)
  {
  NTSTATUS res;
  PKBDDRIVER_DEVICE_EXTENSION MainDx = (PKBDDRIVER_DEVICE_EXTENSION)dx->MainFdo->DeviceExtension;
  MainDx->LastDeviceNumber = dx->InputDeviceNumber;
  MainDx->LastIsKeyboard = dx->IsKeybord;
  IoSkipCurrentIrpStackLocation(Irp);
  res = IoCallDriver(dx->InputDevice, Irp);
  return res;
  }
 else
  {
  ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

  // Диспетчеризация по IOCTL кодам:
  switch(ControlCode)
   {

   case IOCTL_GET_DATA:
    {
    ULONG bufsize = sizeof(INPUT_DATA);
    ULONG OutputLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
    PINPUT_DATA InputData;

    if (OutputLength < bufsize)
     {
     status = STATUS_INVALID_PARAMETER;
     break;
     }

    InputData = (PINPUT_DATA)Irp->AssociatedIrp.SystemBuffer;
    InputData->InputDeviceNumber = dx->LastDeviceNumber;
    InputData->IsKeyboard = dx->LastIsKeyboard;

    dx->LastDeviceNumber = -1;
    dx->LastIsKeyboard = -1;

    BytesTxd = bufsize;
    break;
    }

   // Ошибочный запрос (код IOCTL, который не обрабатывается):
   default: status = STATUS_INVALID_DEVICE_REQUEST;
   }

  return CompleteIrp(Irp, status, BytesTxd); // Завершение IRP
  }
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
 PKBDDRIVER_DEVICE_EXTENSION dx;
 PKTHREAD pThreadObject;
 LONG Prev;
 ULONG i;

 #if DBG
  DbgPrint("K: In Unload Routine\n");
 #endif

 pNextDevObj = pDriverObject->DeviceObject;
 dx = (PKBDDRIVER_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;

 dx =(PKBDDRIVER_DEVICE_EXTENSION)dx->MainFdo->DeviceExtension;

 dx->StopReadFreeInput = TRUE;

 for (i = 0; i < dx->FreeInputDeviceCount; i++)
  {
  NTSTATUS res = ZwSetEvent(dx->ReadEvent[i], &Prev);
  #if DBG
   DbgPrint("K: ZwSetEvent %X = %X\n", dx->ReadEvent[i], res);
  #endif
  }

 for (i = 0; i < dx->FreeInputDeviceCount; i++)
  {
  NTSTATUS res = ObReferenceObjectByHandle(dx->ReadThreads[i], THREAD_ALL_ACCESS, NULL, KernelMode,
   (PVOID *)&pThreadObject, NULL);

  if(NT_SUCCESS(res))
   {
   KeWaitForSingleObject( (PVOID)pThreadObject, Suspended, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
   ObDereferenceObject(pThreadObject);
   }
  #if DBG
   DbgPrint("K: KeWaitForSingleObject Tread %X\n", dx->ReadThreads[i]);
  #endif
  }

 #if DBG
  DbgPrint("K: All read threads stopped\n");
 #endif

 pNextDevObj = pDriverObject->DeviceObject;
 dx = (PKBDDRIVER_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;

 for(i = 0; pNextDevObj != NULL; i++)
  {
  PKBDDRIVER_DEVICE_EXTENSION dx =
    (PKBDDRIVER_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;

  if (dx->IsInputDevice)
   {
   #if DBG
    DbgPrint("K: dx->InputDevice %X\n", dx->InputDevice);
    DbgPrint("K: dx->IsKeybord %X\n", dx->IsKeybord);
    DbgPrint("K: dx->InputDeviceNumber %X\n", dx->InputDeviceNumber);
   #endif

   if (dx->InputDevice)
    {
    PDEVICE_OBJECT TmpObj = IoGetDeviceAttachmentBaseRef(pNextDevObj);
    #if DBG
     DbgPrint("K: TmpObj %X\n", TmpObj);
    #endif
    if (TmpObj && (TmpObj != pNextDevObj))
     {
     IoDetachDevice(dx->InputDevice);
     ObDereferenceObject(TmpObj);
     }
    }

   #if DBG
    DbgPrint("!!!!K: IoDetachDevice !!!!\n");
   #endif
   }

  pNextDevObj = pNextDevObj->NextDevice;

  if (!dx->IsInputDevice)
   {
   IoDeleteSymbolicLink(&dx->SymLinkName);
   }

  IoDeleteDevice(dx->fdo);
  }
 }
#pragma code_seg() // end PAGE section



