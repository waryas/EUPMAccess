#pragma once
#include <windows.h>
#include <winternl.h>

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT, *PSECTION_INHERIT;

extern "C" NTSTATUS NTAPI	ZwOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
extern "C" NTSTATUS NTAPI	ZwMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
											   _Inout_ PVOID BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
											   _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
											   _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
											   _In_ ULONG Win32Protect);
extern "C" NTSTATUS NTAPI	ZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

#pragma comment(lib, "ntdll.lib")
