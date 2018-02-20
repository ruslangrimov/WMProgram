#ifndef _GENERAL_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
#define _GENERAL_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
//----------------------------------------------------------------------------------------------------
// (Файл general.h)
// Тут объявлены все структуры, общие для всех модулей
//----------------------------------------------------------------------------------------------------

#include <ntifs.h>
#include "ntinclude.h"
#include "ioctlcodes.h"
#include "..\newdrv\ntcallhooks.h"

//----------------------------------------------------------------------------------------------------
// Основные константы
//----------------------------------------------------------------------------------------------------
#define MAIN_DEVICE L"WMDEVICE"
#define MAIN_SYM_LINK_NAME L"\\DosDevices\\WMDevice"
#define MAIN_DEVICE_NAME L"\\Device\\WMDEVICE"
#define CANCLOSE_EVENT_NAME L"\\WM_Can_Shutdown"
#define CANCLOSE_EVENT_SYMLINK_NAME L"\\BaseNamedObjects\\WM_Can_Shutdown"
#define WAIT_ANSWERS_CANCLOSE_EVENT_NAME L"\\Wait_WM_Can_Shutdown"
#define WAIT_ANSWERS_CANCLOSE_EVENT_SYMLINK_NAME L"\\BaseNamedObjects\\Wait_WM_Can_Shutdown"
#define AFDHOOK_PATH L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Afdhook\\"
#define PROG_PATH L"\\REGISTRY\\MACHINE\\SYSTEM\\WMSettings\\"
#define SERVICE_PATH L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WMService\\"

#define TAG 'Tg'

//----------------------------------------------------------------------------------------------------
// Специальные константы
//----------------------------------------------------------------------------------------------------
#define UTIL_NAME "WMProgram.exe"
#define VERSION 0x00000002
#define DEMO 0
#define INCLUDE_SECR_CODE 0 //влючать ли зашифрованный участок кода
#define AES_KEY_SIZE 32 //размер ключа для шифрования в байтах
#define MAX_DEMO_STARTUP 50
#define DEMO_REG_STARTUP_COUNT L"Attach.ToDesktop"

//----------------------------------------------------------------------------------------------------
// Структура расширения устройства
//----------------------------------------------------------------------------------------------------
typedef struct _DRIVER_DEVICE_EXTENSION
 {
 PDEVICE_OBJECT fdo;
 UNICODE_STRING SymLinkName;
 WCHAR SymLinkNameBuf[32];
 NTSTATUS GlobStatus;
 BOOLEAN StartOnBoot; //сервис стартовал при запуске
 PSETTINGS StartSettings; //настройки, с которыми стартовал сервис
 ULONG Sessions[10]; //индек массива - номер рабочего места, значение - номер сессии windows
 BOOLEAN InSessionStart; //
 ULONG LastWorkstation; //номер последнего рабочего места (нумерация начинается с 0)
 PDEVICE_OBJECT KeyboardsPDO[10]; //индеск массива - номер устройства, значение - PDO устройства
 PDEVICE_OBJECT PointersPDO[10]; //индеск массива - номер устройства, значение - PDO устройства
 BOOLEAN CanContinueShutdown; //общее согласие или несогласие завершения работы
 BOOLEAN CanContinueAnswers[10]; //ответило ли рабочее место на вопрос о завершении работы
 BOOLEAN IsLogged[10]; //залогинено ли рабочее место
 BOOLEAN TotalCanContinueShutdown; //ставится в true при согласии всех завершить работу, для того чтобы более опросов не проводилось
 ULONG ShutdownInitiator; //рабочее место - инициатор завершения работы системы
 BOOLEAN ShutdownInitiatorCancel; //инициатор отменил завершение работы
 BOOLEAN SessionsStarted; //сессии запущены

 ULONG HaveAllConsoleDevices; //0x0 - для консольного рабочего места указаны все устройства и они подключены в данный момент, иначе код ошибки
 ULONG CanDemoStartSession1; //Можно ли запускать сессии в демо-версии. 0x4 - можно запустить сессии, прочее - нельзя
 ULONG CanDemoStartSession2; //Можно ли запускать сессии в демо-версии. 0x1 - можно запустить сессии, 0x2 - нельзя
 BOOLEAN IsRegisterCopy; //зарегистрированная копия полной версии программы
 ULONG CanDemoStartSession3; //Никак не используется

 CHAR NullSessionProcList[1024]; //список процессов, при запросе текущей сессии, которым надо возвращать нулевую сессию
 ULONG EnableMultipleTSSessions; //Включить возможность включения быстрогопереключения пользователей
 ULONG DisableHostDeviceCheck; //Отключить проверку наличия клавиатуры, мыши и монитора для основного рабочего места

 PDEVICE_OBJECT HidsPDO[10]; //индекс массива - номер устройства, значение - PDO устройства

 NtCreateEvent_PTR OrigFuncNtCreateEvent;
 NtCreateDirectoryObject_PTR OrigFuncNtCreateDirectoryObject;
 NtOpenFile_PTR OrigFuncNtOpenFile;
 NtQueryInformationProcess_PTR OrigFuncNtQueryInformationProcess;
 NtQueryInformationToken_PTR OrigFuncNtQueryInformationToken;
 NtSetSystemInformation_PTR OrigFuncNtSetSystemInformation;
 NtCreatePort_PTR OrigFuncNtCreatePort;
 NtCreateFile_PTR OrigFuncNtCreateFile;
 NtQueryValueKey_PTR OrigFuncNtQueryValueKey;
 NtSetValueKey_PTR OrigFuncNtSetValueKey;
 NtRequestWaitReplyPort_PTR OrigFuncNtRequestWaitReplyPort;
 NtSecureConnectPort_PTR OrigFuncNtSecureConnectPort;
 NtOpenDirectoryObject_PTR OrigFuncNtOpenDirectoryObject;
 }
DRIVER_DEVICE_EXTENSION, *PDRIVER_DEVICE_EXTENSION;

//----------------------------------------------------------------------------------------------------
// Функции
//----------------------------------------------------------------------------------------------------
NTSTATUS SearchDevice(PDEVICE_OBJECT *pDeviceObject, PCWSTR cwDeviceName); //Поиск устройства по имени
PDRIVER_DEVICE_EXTENSION GetDx(); //Функция возвращающая device extension главного сервиса
ULONG GetWorkStationNumber(PDRIVER_DEVICE_EXTENSION dx); //Функция возвращающая номер текущей рабочей станции
LONG MyCompareUnicodeString(PUNICODE_STRING Str, PWCHAR Buffer); //Сравнение UNICODE строки и UNICODE буфера
LONG MyCompareUnicodeStringI(PUNICODE_STRING Str, PWCHAR Buffer); //Сравнение UNICODE строки и UNICODE буфера без учёта регистра
PWCHAR MyStrUnicodeString(PUNICODE_STRING Str, PWCHAR Buffer); //Поиск подстроки в UNICODE строке
//PWCHAR MyStrUnicodeStringI(PUNICODE_STRING Str, PWCHAR Buffer); //Поиск подстроки в UNICODE строке без учёта регистра
#endif