/////////////////////////////////////////////////////////////////////////////
//
//                      FastIO Handling routines
//
/////////////////////////////////////////////////////////////////////////////

//
// Модуль скопирован из примеров DDK sfilter и чуть изменён

#include "fastio.h"

BOOLEAN
SfFastIoCheckIfPossible (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in BOOLEAN CheckForReadOperation,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoCheckIfPossible )) {

            return (fastIoDispatch->FastIoCheckIfPossible)(
                        FileObject,
                        FileOffset,
                        Length,
                        Wait,
                        LockKey,
                        CheckForReadOperation,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoRead )) {

            return (fastIoDispatch->FastIoRead)(
                        FileObject,
                        FileOffset,
                        Length,
                        Wait,
                        LockKey,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoWrite )) {

            return (fastIoDispatch->FastIoWrite)(
                        FileObject,
                        FileOffset,
                        Length,
                        Wait,
                        LockKey,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoQueryBasicInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_BASIC_INFORMATION)) PFILE_BASIC_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryBasicInfo )) {

            return (fastIoDispatch->FastIoQueryBasicInfo)(
                        FileObject,
                        Wait,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoQueryStandardInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_STANDARD_INFORMATION)) PFILE_STANDARD_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoQueryStandardInfo )) {

            return (fastIoDispatch->FastIoQueryStandardInfo)(
                        FileObject,
                        Wait,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoLock (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoLock )) {

            return (fastIoDispatch->FastIoLock)(
                        FileObject,
                        FileOffset,
                        Length,
                        ProcessId,
                        Key,
                        FailImmediately,
                        ExclusiveLock,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoUnlockSingle (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoUnlockSingle )) {

            return (fastIoDispatch->FastIoUnlockSingle)(
                        FileObject,
                        FileOffset,
                        Length,
                        ProcessId,
                        Key,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoUnlockAll (
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (nextDeviceObject) {

            if (!nextDeviceObject->DriverObject)
             return FALSE;

            fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

            if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                                FastIoUnlockAll )) {

                return (fastIoDispatch->FastIoUnlockAll)(
                            FileObject,
                            ProcessId,
                            IoStatus,
                            nextDeviceObject );
            }
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoUnlockAllByKey (
    __in PFILE_OBJECT FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoUnlockAllByKey )) {

            return (fastIoDispatch->FastIoUnlockAllByKey)(
                        FileObject,
                        ProcessId,
                        Key,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoDeviceControl (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoDeviceControl )) {

            return (fastIoDispatch->FastIoDeviceControl)(
                        FileObject,
                        Wait,
                        InputBuffer,
                        InputBufferLength,
                        OutputBuffer,
                        OutputBufferLength,
                        IoControlCode,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


VOID
SfFastIoDetachDevice (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice
    )

{
    PAGED_CODE();

    //SfCleanupMountedDevice( SourceDevice );
     #if DBG
      DbgPrint("MF: FSCTL_DISMOUNT_VOLUME TargetDevice: %X\n", TargetDevice);
      DbgPrint("MF: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
     #endif

    IoDetachDevice( TargetDevice );
    IoDeleteDevice( SourceDevice );
}


BOOLEAN
SfFastIoQueryNetworkOpenInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoQueryNetworkOpenInfo )) {

            return (fastIoDispatch->FastIoQueryNetworkOpenInfo)(
                        FileObject,
                        Wait,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoMdlRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlRead )) {

            return (fastIoDispatch->MdlRead)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        MdlChain,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoMdlReadComplete (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlReadComplete )) {

            return (fastIoDispatch->MdlReadComplete)(
                        FileObject,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoPrepareMdlWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, PrepareMdlWrite )) {

            return (fastIoDispatch->PrepareMdlWrite)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        MdlChain,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoMdlWriteComplete (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            MdlWriteComplete )) {

            return (fastIoDispatch->MdlWriteComplete)(
                        FileObject,
                        FileOffset,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoReadCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __out_bcount(CompressedDataInfoLength) struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoReadCompressed )) {

            return (fastIoDispatch->FastIoReadCompressed)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        Buffer,
                        MdlChain,
                        IoStatus,
                        CompressedDataInfo,
                        CompressedDataInfoLength,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoWriteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __out_bcount(CompressedDataInfoLength) struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoWriteCompressed )) {

            return (fastIoDispatch->FastIoWriteCompressed)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        Buffer,
                        MdlChain,
                        IoStatus,
                        CompressedDataInfo,
                        CompressedDataInfoLength,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoMdlReadCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            MdlReadCompleteCompressed )) {

            return (fastIoDispatch->MdlReadCompleteCompressed)(
                        FileObject,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoMdlWriteCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            MdlWriteCompleteCompressed )) {

            return (fastIoDispatch->MdlWriteCompleteCompressed)(
                        FileObject,
                        FileOffset,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
SfFastIoQueryOpen (
    __in PIRP Irp,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    BOOLEAN result;

    PAGED_CODE();

    if (((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol) {
        nextDeviceObject = ((PTCPDRIVER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->Protocol;

        if (!nextDeviceObject->DriverObject)
         return FALSE;

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryOpen )) {

            PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation( Irp );

            //
            //  Before calling the next filter, we must make sure their device
            //  object is in the current stack entry for the given IRP
            //

            irpSp->DeviceObject = nextDeviceObject;

            result = (fastIoDispatch->FastIoQueryOpen)(
                        Irp,
                        NetworkInformation,
                        nextDeviceObject );

            //
            //  Always restore the IRP back to our device object
            //

            irpSp->DeviceObject = DeviceObject;
            return result;
        }
    }
    return FALSE;
}