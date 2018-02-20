
#include "general.h"

//----------------------------------------------------------------------------------------------------
// Сравнение двух UNICODE_STRING [!!!] заменить на RtlCompareUnicodeString
//----------------------------------------------------------------------------------------------------
BOOLEAN mywcsncmp(PCWSTR Str1, PCWSTR Str2, ULONG Size)
 {
 __try
  {
  return (wcsncmp(Str1, Str2, Size / 2) == 0);
  }
 __except(EXCEPTION_EXECUTE_HANDLER)
  {
  return FALSE;
  }
 }

//----------------------------------------------------------------------------------------------------
// Функция возвращающая номер текущей рабочей станции
//----------------------------------------------------------------------------------------------------
NTSTATUS SearchDevice(PDEVICE_OBJECT *pFindObject, PCWSTR cwDeviceName)
 {
 OBJECT_ATTRIBUTES ObjectAttributes;
 UNICODE_STRING uDirName;
 NTSTATUS status = STATUS_SUCCESS;
 HANDLE hDirectory = NULL;
 POBJECT_DIRECTORY pDirectoryObject = NULL;
 KIRQL OldIrql;
 POBJECT_HEADER ObjectHeader;
 POBJECT_HEADER_NAME_INFO NameInfo;
 POBJECT_DIRECTORY_ENTRY DirectoryEntry;
 POBJECT_DIRECTORY_ENTRY DirectoryEntryNext;
 POBJECT_DIRECTORY_ENTRY DirectoryEntryTop;
 ULONG Bucket = 0;
 UNICODE_STRING ObjectName;
 RtlInitUnicodeString(&uDirName, L"\\Device");
 InitializeObjectAttributes(&ObjectAttributes, &uDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

 *pFindObject = NULL;

 status = ObOpenObjectByName(&ObjectAttributes, NULL, 0, 0, GENERIC_READ, NULL, &hDirectory);

 if (status == STATUS_SUCCESS)
  {
  status = ObReferenceObjectByHandle(hDirectory, FILE_ANY_ACCESS, NULL, KernelMode,(PVOID *)&pDirectoryObject, NULL);
  if (status == STATUS_SUCCESS)
   {
   KeRaiseIrql(APC_LEVEL, &OldIrql);

   for (Bucket = 0; Bucket < NUMBER_HASH_BUCKETS; Bucket++)
    {
    if (*pFindObject)
     break;

    DirectoryEntry = pDirectoryObject->HashBuckets[Bucket];
    if (!DirectoryEntry)
     continue;

    ObjectHeader = OBJECT_TO_OBJECT_HEADER(DirectoryEntry->Object);
    NameInfo = OBJECT_HEADER_TO_NAME_INFO(ObjectHeader);

    if (NameInfo != NULL)
     {
     ObjectName = NameInfo->Name;
     // [!!!] заменить на RtlCompareUnicodeString
     if (mywcsncmp(ObjectName.Buffer, cwDeviceName, ObjectName.Length))
      {
      *pFindObject = (PDEVICE_OBJECT)DirectoryEntry->Object;
      break;
      }
     }

    DirectoryEntryNext = DirectoryEntry->ChainLink;

    while (DirectoryEntryNext)
     {
     ObjectHeader = OBJECT_TO_OBJECT_HEADER(DirectoryEntryNext->Object);
     NameInfo = OBJECT_HEADER_TO_NAME_INFO (ObjectHeader);

     if (NameInfo != NULL)
      {
      ObjectName = NameInfo->Name;
      // [!!!] заменить на RtlCompareUnicodeString
      if (mywcsncmp(ObjectName.Buffer, cwDeviceName, ObjectName.Length))
       {
       *pFindObject = (PDEVICE_OBJECT)DirectoryEntryNext->Object;
       break;
       }
      }

     if (DirectoryEntry)
      {
      DirectoryEntry = DirectoryEntry->ChainLink;
      DirectoryEntryNext = DirectoryEntry->ChainLink;
      }
     else
      DirectoryEntryNext = NULL;
     }
    }

   KeLowerIrql(OldIrql);
   ObDereferenceObject(pDirectoryObject);
   }
  else
   {
   #if DBG
    DbgPrint("T: Error ObReferenceObjectByHandle %X\n", status);
   #endif
   }

  ZwClose(hDirectory);
  }
 else
  {
  #if DBG
   DbgPrint("T: Error ObOpenObjectByName %X\n", status);
  #endif
  }

 return status;
 }

//----------------------------------------------------------------------------------------------------
// Функция возвращающая device extension главного сервиса
//----------------------------------------------------------------------------------------------------
PDRIVER_DEVICE_EXTENSION GetDx()
 {
 PDEVICE_OBJECT fdo;
 SearchDevice(&fdo, MAIN_DEVICE);
 if (fdo)
  return (PDRIVER_DEVICE_EXTENSION)fdo->DeviceExtension;
 else
  return NULL;
 }

//----------------------------------------------------------------------------------------------------
// Функция возвращающая номер текущей рабочей станции
//----------------------------------------------------------------------------------------------------
ULONG GetWorkStationNumber(PDRIVER_DEVICE_EXTENSION dx)
 {
 ULONG ThisWorkStation = -2;
 ULONG i;
 //
 //DbgPrint("!!!!T: dx %X\n", dx);
 //DbgPrint("!!!!T: dx->Sessions %X\n", &dx->Sessions);
 //for (int i = 0; i < 10; i ++)
 // DbgPrint("!!!!T: dx->Sessions[i] %X\n", dx->Sessions[i]);
 //

 for (i = 0; i < 10; i ++)
  if (dx->Sessions[i] == PsGetCurrentProcessSessionId())
   {
   ThisWorkStation = i + 1;
   break;
   }
 return ThisWorkStation;
 }

//----------------------------------------------------------------------------------------------------
// Функция для сравнения UNICODE строки и UNICODE буфера без учёта регистра
//----------------------------------------------------------------------------------------------------
LONG MyCompareUnicodeStringI(PUNICODE_STRING Str, PWCHAR Buffer)
 {
 ULONG BufLen = wcslen(Buffer) * 2;
 LONG res;

 if (BufLen == Str->Length)
  res = _wcsnicmp(Str->Buffer, Buffer, BufLen);
 else
  {
  if (Str->Length < BufLen)
   res = -1;
  else
   res = 1;
  }

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция для сравнения UNICODE строки и UNICODE буфера
//----------------------------------------------------------------------------------------------------
LONG MyCompareUnicodeString(PUNICODE_STRING Str, PWCHAR Buffer)
 {
 ULONG BufLen = wcslen(Buffer) * 2;
 LONG res;

 if (BufLen == Str->Length)
  res = wcsncmp(Str->Buffer, Buffer, BufLen);
 else
  {
  if (Str->Length < BufLen)
   res = -1;
  else
   res = 1;
  }

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция для поиска подстроки в строке UNICODE
//----------------------------------------------------------------------------------------------------
PWCHAR MyStrUnicodeString(PUNICODE_STRING Str, PWCHAR Buffer)
 {
 //PWCHAR res = NULL;
 //res = wcsstr(Str->Buffer, Buffer);
 LONG i;
 LONG Length, BufLen;
 PWCHAR res = NULL;

 BufLen = wcslen(Buffer);
 Length = (Str->Length / 2 - BufLen) + 1;

 for (i = 0; i < Length; i++)
  {
  if (!memcmp(&Str->Buffer[i], Buffer, BufLen * 2))
   {
   res = &Str->Buffer[i];
   break;
   }

  }

 return res;
 }

//----------------------------------------------------------------------------------------------------
// Функция для поиска подстроки в строке UNICODE
//----------------------------------------------------------------------------------------------------
/*PWCHAR MyStrUnicodeStringI(PUNICODE_STRING Str, PWCHAR Buffer)
 {
 RtlUpcaseUnicodeString(Str, Str, FALSE);
 _wcsupr(Buffer);
 return MyStrUnicodeString(Str, Buffer);
 }*/