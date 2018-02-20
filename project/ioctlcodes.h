#ifndef _IOCTLCODES_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
#define _IOCTLCODES_H_04802_BASHBD_1UIWQ1_8239_1NJKDH832_901_
//----------------------------------------------------------------------------------------------------
// (Файл ioctlcodes.h)
// Тут объявлены структуры, IOCTL коды - для обмена информацией с драйверами из Ring3
//----------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------
// Структуры для передачи данных между драйвером и приложением
//----------------------------------------------------------------------------------------------------

#define SECR_CODE_SIZE 512 //размер куска очень секретного кода

// Информация о видеоустройствах
typedef struct _VIDEO_DEVICE_INFO {
 ULONG VideoNumber;
 wchar_t VideoDescription[64];
 wchar_t MonitorDescription[64];
} VIDEO_DEVICE_INFO, *PVIDEO_DEVICE_INFO;

typedef struct _VIDEO_DEVICES_INFO {
 ULONG iDeviceCount;
 VIDEO_DEVICE_INFO VideoDevices[10];
} VIDEO_DEVICES_INFO, *PVIDEO_DEVICES_INFO;

// Информация о HID-устройствах
typedef struct _HID_DEVICE_INFO {
 wchar_t HidKeyName[64];
 wchar_t HidDescription[64];
} HID_DEVICE_INFO, *PHID_DEVICE_INFO;

typedef struct _HID_DEVICES_INFO {
 ULONG iDeviceCount;
 HID_DEVICE_INFO HidDevices[10];
} HID_DEVICES_INFO, *PHID_DEVICES_INFO;

// Информация о устройствах ввода
typedef enum _INPUT_DEVICE_TYPE {
 Keyboard,
 Pointer
} INPUT_DEVICE_TYPE, *PINPUT_DEVICE_TYPE;

typedef struct _INPUT_DEVICE_INFO {
 ULONG InputNumber;
 wchar_t InputDescription[256];
 INPUT_DEVICE_TYPE InputType;
} INPUT_DEVICE_INFO, *PINPUT_DEVICE_INFO;

typedef struct _INPUT_DEVICES_INFO {
 ULONG iDeviceCount;
 INPUT_DEVICE_INFO InputDevices[10];
} INPUT_DEVICES_INFO, *PINPUT_DEVICES_INFO;

typedef struct _HID_DEVICE_SETTING {
 wchar_t HidKeyName[64];
 ULONG Mask;
 } HID_DEVICE_SETTING, *PHID_DEVICE_SETTING;

typedef struct _SETTINS {
 ULONG WorkstationsCount;
 ULONG Video[10];
 ULONG Keyboards[10];
 ULONG Pointers[10];
 ULONG EnableIP;
 ULONG IPs[10];
 ULONG AutoStart;
 ULONG GlobTerminalVar; //обнулять ли глобальную переменную в версии виндоус
 BYTE Data[SECR_CODE_SIZE];
 HID_DEVICE_SETTING Hids[10];
 ULONG EnableCPU;
 ULONG EnableCPUForAll; //пока не используется
 ULONG CPUMask[10];
} SETTINGS, *PSETTINGS;

//----------------------------------------------------------------------------------------------------
// Собственные коды IOCTL
//----------------------------------------------------------------------------------------------------
//стартовать новые сессии
#define IOCTL_START_NEW_SESSION CTL_CODE( \
 FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

//получить информацию о видеоустройствах
#define IOCTL_GET_VIDEO_DEVICE_INFO CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//получить информацию о клавиатурах
#define IOCTL_GET_KEYBOARD_DEVICE_INFO CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

//получить информацию о мышах
#define IOCTL_GET_POINTER_DEVICE_INFO CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

//получить настройки (текущие из реестра)
#define IOCTL_GET_SETTINGS CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

//получить настройки (стартовые)
#define IOCTL_GET_START_SETTINGS CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

//сохранить настройки
#define IOCTL_SET_SETTINGS CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

//узнать, запускается ли служба автоматом
#define IOCTL_GET_START_TYPE CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SET_START_TYPE CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

//ответить, можно ли завершить текущее рабочее место
#define IOCTL_SET_CONTINUE_SHUTDOWN CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

//узнать, является ли данная станция инициатором завершения работы
#define IOCTL_GET_IS_CURRENT_SHUTDOWN CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Установить, залогинена/незалогинена текущая станция
#define IOCTL_SET_IS_LOGGED CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Получить номер текущего рабочего места
#define IOCTL_GET_WORKSTATION_NUMBER CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Узнать, стартовал ли сервис при загрузке
#define IOCTL_GET_START_ON_BOOT CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Узнать, запущены ли сессии
#define IOCTL_GET_SESSIONS_STARTED CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Узнать, есть ли все устройства для консоли
#define IOCTL_GET_HAVE_ALL_CONSOLE_DEVICES CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Узнать, демонстрационная ли это версия
#define IOCTL_GET_IS_DEMO CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Узнать, зарегистрированная ли это копия
#define IOCTL_GET_IS_REGISTER_COPY CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Получить ключ из HardwareId для AES шифрования
#define IOCTL_GET_AES_KEY CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Сохранить очень секретный код
#define IOCTL_SET_SECRET_CODE CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Узнать реальный номер сессии
#define IOCTL_GET_REAL_SESSION_ID CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

//получить информацию о HID устройствах
#define IOCTL_GET_HID_DEVICE_INFO CTL_CODE(\
 FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)


//Коды для клавиатурного фильтра
#define IOCTL_GET_DATA CTL_CODE( \
 FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

//----------------------------------------------------------------------------------------------------
//Команды для dll Ring3
//----------------------------------------------------------------------------------------------------
#define ShowWorkstationNumber 1 //показать номера рабочих станций
#define RefreshDisplay 2 //обновить дисплеи

//----------------------------------------------------------------------------------------------------
//Статусы пользовательских ошибок
//----------------------------------------------------------------------------------------------------
#define STATUS_CANT_CREATE_SS_THREAD                   0x1000
#define STATUS_CANT_OPEN_SMAPIPORT                     0x2000
#define STATUS_CANT_SEND_MESSAGE                       0x3000
#define STATUS_SMSS_RETURN_ERROR                       0x4000
#define STATUS_INVALID_BUFSIZE_FOR_VIDEO               0x5000
#define STATUS_SEARCH_DEVICE_ERROR                     0x6000
#define STATUS_VIDEOINFO_CALL_DRIVER                   0x7000
#define STATUS_OPEN_VIDEO_KEY                          0x8000
#define STATUS_OPEN_KEYBOARD_KEY                       0x9000
#define STATUS_INVALID_BUFSIZE_FOR_INPUT               0xA000
#define STATUS_INVALID_BUFSIZE_FOR_SETTING             0xB000

#define STATUS_NO_KEYBOARD_FOR_CONCOLE                 0xE0000001
#define STATUS_NO_POINTER_FOR_CONCOLE                  0xE0000002
#define STATUS_NO_VIDEO_FOR_CONCOLE                    0xE0000003

#define STATUS_INVALID_SECRET_CODE                     0xE0000010
#define STATUS_VERSION_NOT_REGISTER                    0xE0000011
#define STATUS_INVALID_SECRET_CODE_VERSION             0xE0000012

#endif