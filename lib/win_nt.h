/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef WIN_NT_HEADER
#define WIN_NT_HEADER


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} DUNICODE_STRING, * PDUNICODE_STRING;

FORCEINLINE VOID RtlInitUnicodeString(
    _Out_ PDUNICODE_STRING DestinationString,
    _In_opt_ PWSTR SourceString
)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(WCHAR);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = SourceString;
}

typedef _Success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        LONG Status;
        PVOID Pointer;
    };
    ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PDUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} DOBJECT_ATTRIBUTES, * PDOBJECT_ATTRIBUTES;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


typedef NTSTATUS(*_NtCreateFile)(
    _In_          PHANDLE            FileHandle,
    _In_           ACCESS_MASK        DesiredAccess,
    _In_           PDOBJECT_ATTRIBUTES ObjectAttributes,
    _Out_          PIO_STATUS_BLOCK   IoStatusBlock,
    _In_opt_       PLARGE_INTEGER     AllocationSize,
    _In_           ULONG              FileAttributes,
    _In_           ULONG              ShareAccess,
    _In_           ULONG              CreateDisposition,
    _In_           ULONG              CreateOptions,
    _In_           PVOID              EaBuffer,
    _In_           ULONG              EaLength
    );

typedef NTSTATUS(*_NtReadFile)(
    _In_     HANDLE           FileHandle,
    _In_opt_ HANDLE           Event,
    _In_opt_ PIO_APC_ROUTINE  ApcRoutine,
    _In_opt_ PVOID            ApcContext,
    _Out_    PIO_STATUS_BLOCK IoStatusBlock,
    _Out_    PVOID            Buffer,
    _In_     ULONG            Length,
    _In_opt_ PLARGE_INTEGER   ByteOffset,
    _In_opt_ PULONG           Key
    );

typedef NTSTATUS(*_NtClose)(
    _In_ HANDLE Handle
    );

#endif
