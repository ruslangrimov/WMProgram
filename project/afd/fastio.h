#ifndef _DRIVER_H_FASTIO_
#define _DRIVER_H_FASTIO_

#include "Driver.h"

#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
    (((_FastIoDispatchPtr) != NULL) && \
     (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
            (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
     ((_FastIoDispatchPtr)->_FieldName != NULL))

//заглушки
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
    );

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
    );

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
    );

BOOLEAN
SfFastIoQueryBasicInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_BASIC_INFORMATION)) PFILE_BASIC_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoQueryStandardInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_STANDARD_INFORMATION)) PFILE_STANDARD_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

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
    );

BOOLEAN
SfFastIoUnlockSingle (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoUnlockAll (
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoUnlockAllByKey (
    __in PFILE_OBJECT FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

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
    );

VOID
SfFastIoDetachDevice (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice
    );

BOOLEAN
SfFastIoQueryNetworkOpenInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );


BOOLEAN
SfFastIoMdlReadComplete (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoPrepareMdlWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlWriteComplete (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

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
    );

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
    );

BOOLEAN
SfFastIoMdlReadCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlWriteCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoQueryOpen (
    __in PIRP Irp,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT DeviceObject
    );

#endif