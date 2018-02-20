//---------------------------------------------------------------------------
// Фильтр AFD устройства
//---------------------------------------------------------------------------

#include "driver.h"
#include "fastio.h"

// Предварительное объявление функций:
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);

NTSTATUS MyPassThru(PDEVICE_OBJECT fdo, PIRP theIRP);
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp);
NTSTATUS DispatchAfdBind(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp);

#define AFDHOOK_SYM_LYNK_NAME L"\\DosDevices\\AfdHook"
#define AFDHOOK_DEVICE_NAME L"\\Device\\AFDHOOK"
#define PROTOCOL_DEVICE_NAME L"Afd\\Endpoint"

#pragma code_seg("INIT") // начало секции INIT
//---------------------------------------------------------------------------
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
 {
 NTSTATUS status = STATUS_SUCCESS;
 PDEVICE_OBJECT fdo = NULL;
 UNICODE_STRING devName;
 PFAST_IO_DISPATCH fastIoDispatch = NULL;
 ULONG i;

 PTCPDRIVER_DEVICE_EXTENSION dx;
 UNICODE_STRING symLinkName;
 __try
  {
  #if DBG
   DbgPrint("T: In DriverEntry\n");
   DbgPrint("T: RegistryPath = %wZ\n", RegistryPath);
  #endif

  for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
   DriverObject->MajorFunction[i] = MyPassThru;
  DriverObject->DriverUnload = UnloadRoutine;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchAfdBind;

  fastIoDispatch = (PFAST_IO_DISPATCH)ExAllocatePoolWithTag( NonPagedPool, sizeof( FAST_IO_DISPATCH ), SFLT_POOL_TAG_FASTIO );
  if (!fastIoDispatch)
   {
   return STATUS_INSUFFICIENT_RESOURCES;
   }

  RtlZeroMemory(fastIoDispatch, sizeof(FAST_IO_DISPATCH));

  fastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
  fastIoDispatch->FastIoCheckIfPossible = SfFastIoCheckIfPossible;
  fastIoDispatch->FastIoRead = SfFastIoRead;
  fastIoDispatch->FastIoWrite = SfFastIoWrite;
  fastIoDispatch->FastIoQueryBasicInfo = SfFastIoQueryBasicInfo;
  fastIoDispatch->FastIoQueryStandardInfo = SfFastIoQueryStandardInfo;
  fastIoDispatch->FastIoLock = SfFastIoLock;
  fastIoDispatch->FastIoUnlockSingle = SfFastIoUnlockSingle;
  fastIoDispatch->FastIoUnlockAll = SfFastIoUnlockAll;
  fastIoDispatch->FastIoUnlockAllByKey = SfFastIoUnlockAllByKey;
  fastIoDispatch->FastIoDeviceControl = SfFastIoDeviceControl;
  fastIoDispatch->FastIoDetachDevice = SfFastIoDetachDevice;
  fastIoDispatch->FastIoQueryNetworkOpenInfo = SfFastIoQueryNetworkOpenInfo;
  fastIoDispatch->MdlRead = SfFastIoMdlRead;
  fastIoDispatch->MdlReadComplete = SfFastIoMdlReadComplete;
  fastIoDispatch->PrepareMdlWrite = SfFastIoPrepareMdlWrite;
  fastIoDispatch->MdlWriteComplete = SfFastIoMdlWriteComplete;
  fastIoDispatch->FastIoReadCompressed = SfFastIoReadCompressed;
  fastIoDispatch->FastIoWriteCompressed = SfFastIoWriteCompressed;
  fastIoDispatch->MdlReadCompleteCompressed = SfFastIoMdlReadCompleteCompressed;
  fastIoDispatch->MdlWriteCompleteCompressed = SfFastIoMdlWriteCompleteCompressed;
  fastIoDispatch->FastIoQueryOpen = SfFastIoQueryOpen;

  DriverObject->FastIoDispatch = fastIoDispatch;

  RtlInitUnicodeString(&devName, AFDHOOK_DEVICE_NAME);
  status = IoCreateDevice(DriverObject, sizeof(TCPDRIVER_DEVICE_EXTENSION), &devName,
   FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);

  if (! NT_SUCCESS(status))
   __leave;

  dx = (PTCPDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
  dx->fdo = fdo;  // Обратный указатель
  #if DBG
   DbgPrint("T: FDO %X, DevExt=%X\n", fdo, dx);
  #endif

  wcscpy(dx->SymLinkNameBuf, AFDHOOK_SYM_LYNK_NAME);
  RtlInitUnicodeString( &symLinkName, dx->SymLinkNameBuf);
  dx->SymLinkName = symLinkName;

  // Создаем символьную ссылку
  status = IoCreateSymbolicLink( &symLinkName, &devName );
  if (! NT_SUCCESS(status))
   __leave;

  dx->Protocol = NULL;
  SearchDevice(&dx->Protocol , PROTOCOL_DEVICE_NAME);
  #if DBG
   DbgPrint("T: dx->Protocol  %X\n", dx->Protocol );
  #endif
  if (dx->Protocol)
   {
   fdo->Flags = dx->Protocol->Flags;

   fdo->Flags = fdo->Flags &
    ~DO_DEVICE_INITIALIZING;

   IoAttachDeviceToDeviceStack(fdo, dx->Protocol);
   }
  }

 __finally
  {
  if (! NT_SUCCESS(status))
   {
   if (fastIoDispatch)
    ExFreePool(fastIoDispatch);
   if (fdo)
    IoDeleteDevice(fdo);
   }
  }

 return status;
 }

#pragma code_seg() // end INIT section

#pragma code_seg("PAGE")

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
// передача пакета дальше по стеку
//----------------------------------------------------------------------------------------------------
NTSTATUS MyPassThru(PDEVICE_OBJECT fdo, PIRP Irp)
 {
 NTSTATUS res;
 PTCPDRIVER_DEVICE_EXTENSION dx;

 IoSkipCurrentIrpStackLocation(Irp);
 dx = (PTCPDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
 res = IoCallDriver(dx->Protocol, Irp);
 return res;
 }

//----------------------------------------------------------------------------------------------------
//
//----------------------------------------------------------------------------------------------------
NTSTATUS DispatchAfdBind(IN PDEVICE_OBJECT fdo, IN PIRP Irp)
 {
 ULONG i;
 ULONG ControlCode;
 ULONG InputLength;
 PTCPDRIVER_DEVICE_EXTENSION dx;
 NTSTATUS res;

 PIO_STACK_LOCATION IrpStack=IoGetCurrentIrpStackLocation(Irp);
 ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
 InputLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

 if (ControlCode == 0x00012003)
  {
  PAFD_BIND_DATA BindData = (PAFD_BIND_DATA)Irp->UserBuffer;
  DbgPrint("T: DispatchAfdBind\n");
  if (BindData)
   {
   for (i = 0; i < (ULONG)BindData->Address.TAAddressCount; i ++)
    {
    if (BindData->Address.Address[i].AddressType == TDI_ADDRESS_TYPE_IP)
     {
     PTDI_ADDRESS_IP IPAddress = (PTDI_ADDRESS_IP)BindData->Address.Address[i].Address;
     PTCPDRIVER_DEVICE_EXTENSION dx = (PTCPDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
     PDRIVER_DEVICE_EXTENSION MainDx = GetDx();

     DbgPrint("T: AddressLength %X\n", BindData->Address.Address[i].AddressLength);
     DbgPrint("T: AddressType %X\n", BindData->Address.Address[i].AddressType);
     if (MainDx)
      {
      ULONG WorkStationNumber = GetWorkStationNumber(MainDx);
      DbgPrint("T: MainDx->StartSettings %X\n", MainDx->StartSettings);
      if (WorkStationNumber != -2)
       {
       DbgPrint("T: WorkStationNumber %X\n", WorkStationNumber);
       if (!IPAddress->in_addr) //если нулевой IP адрес
        {
        DbgPrint("T: ===========================\n");
        DbgPrint("T: sin_port %X\n", IPAddress->sin_port);
        DbgPrint("T: in_addr %X\n", IPAddress->in_addr);
        IPAddress->in_addr = MainDx->StartSettings->IPs[WorkStationNumber - 1];
        DbgPrint("T: new in_addr %X\n", IPAddress->in_addr);
        }
       else
        {
        BOOLEAN IsOther = FALSE;
        for (i = 0; i < MainDx->StartSettings->WorkstationsCount; i ++)
         {
         IsOther |= IPAddress->in_addr == MainDx->StartSettings->IPs[i];
         if (IsOther)
          break;
         }

        if (IsOther) //адрес другого рабочего места
         {
         DbgPrint("T: ===========================\n");
         DbgPrint("T: sin_port %X\n", IPAddress->sin_port);
         DbgPrint("T: in_addr %X\n", IPAddress->in_addr);
         IPAddress->in_addr = MainDx->StartSettings->IPs[WorkStationNumber - 1];
         DbgPrint("T: new in_addr %X\n", IPAddress->in_addr);
         }
        }

       }
      }

     DbgPrint("T: sin_port %X\n", IPAddress->sin_port);
     DbgPrint("T: in_addr %X\n", IPAddress->in_addr);
     }
    }
   }
  }

 IoSkipCurrentIrpStackLocation(Irp);
 dx = (PTCPDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
 res = IoCallDriver(dx->Protocol, Irp);
 return res;
 }

//----------------------------------------------------------------------------------------------------
//
//----------------------------------------------------------------------------------------------------
VOID UnloadRoutine(IN PDRIVER_OBJECT pDriverObject)
 {
 PDEVICE_OBJECT pCurDevice;
 #if DBG
  DbgPrint("T: In Unload Routine\n");
 #endif

 pCurDevice = pDriverObject->DeviceObject;
 while (pCurDevice)
  {
  PTCPDRIVER_DEVICE_EXTENSION dx = (PTCPDRIVER_DEVICE_EXTENSION)pCurDevice->DeviceExtension;

  if (dx->Protocol)
   IoDetachDevice(dx->Protocol);
  IoDeleteSymbolicLink(&dx->SymLinkName);

  pCurDevice = pCurDevice->NextDevice;

  IoDeleteDevice(dx->fdo);
  }

 }
#pragma code_seg() // end PAGE section



