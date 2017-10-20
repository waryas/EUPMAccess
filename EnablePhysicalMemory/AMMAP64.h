#pragma once

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

struct IoCommand {
	_In_ uint64_t offset;
	_Out_ uint64_t virtualmemory;
	_Inout_ LARGE_INTEGER read;
};

#define IOCTL_MAPMEMORY 0x9C402580
#define IOCTL_UNMAPMEM 0x9C402584

#define DEVICENAME "\\\\.\\ASMMAP64"


HANDLE OpenDriver();
bool DriverMapMemory(HANDLE, IoCommand*);
bool DriverUnmapMemory(HANDLE, IoCommand*);
bool CloseDriver(HANDLE);