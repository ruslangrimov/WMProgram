#ifndef _DRIVER_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
#define _DRIVER_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
//----------------------------------------------------------------------------------------------------
// (Файл driver.h)
// Заголовочный файл AFD фильтра
//----------------------------------------------------------------------------------------------------

#include <ntifs.h>
#include <TdiKrnl.h>
#include "..\ntinclude.h"
#include "..\ioctlcodes.h"
#include "..\general.h"

#define SFLT_POOL_TAG_FASTIO 'ifFS'

//Расширение устройства драйвера - фильтра
typedef struct _TCPDRIVER_DEVICE_EXTENSION
 {
 PDEVICE_OBJECT fdo;
 UNICODE_STRING SymLinkName;
 WCHAR SymLinkNameBuf[32];
 PDEVICE_OBJECT Protocol;
 }
TCPDRIVER_DEVICE_EXTENSION, *PTCPDRIVER_DEVICE_EXTENSION;

typedef struct _AFD_BIND_DATA
 {
 ULONG ShareType;
 TRANSPORT_ADDRESS   Address;
 }
AFD_BIND_DATA, *PAFD_BIND_DATA;

#endif

