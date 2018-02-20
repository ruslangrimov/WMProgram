#ifndef _DRIVER_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
#define _DRIVER_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
//----------------------------------------------------------------------------------------------------
// (Файл driver.h)
// Заголовочный файл клавиатурно-мышиного фильтра для подсветки текущего устройства
//----------------------------------------------------------------------------------------------------

#include <ntifs.h>
#include "..\ntinclude.h"
#include "..\ioctlcodes.h"
#include "..\general.h"

struct _KBDDRIVER_DEVICE_EXTENSION;

typedef struct _READ_THREAD_DATA
 {
 ULONG iDeviceNumber;
 struct _KBDDRIVER_DEVICE_EXTENSION * dx;
 }
READ_THREAD_DATA, *PREAD_THREAD_DATA;

//Расширение устройства драйвера - фильтра
typedef struct _KBDDRIVER_DEVICE_EXTENSION
 {
 PDEVICE_OBJECT fdo;
 UNICODE_STRING SymLinkName;
 WCHAR SymLinkNameBuf[32];
 ULONG LastDeviceNumber;
 ULONG LastIsKeyboard;
 ULONG FreeInputDeviceCount;
 PDEVICE_OBJECT FreeInputDevices[10];
 BOOLEAN StopReadFreeInput;
 HANDLE ReadThreads[10];
 HANDLE ReadEvent[10];
 READ_THREAD_DATA rd[10];

 PDEVICE_OBJECT MainFdo;
 PDEVICE_OBJECT InputDevice;
 ULONG IsInputDevice;
 ULONG InputDeviceNumber;
 ULONG IsKeybord;
 }
KBDDRIVER_DEVICE_EXTENSION, *PKBDDRIVER_DEVICE_EXTENSION;

typedef struct _INPUT_DATA
 {
 ULONG InputDeviceNumber;
 ULONG IsKeyboard;
 }
INPUT_DATA, *PINPUT_DATA;

#endif

