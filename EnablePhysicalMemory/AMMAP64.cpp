#include "AMMAP64.h"
#include <Windows.h>

HANDLE OpenDriver() {
	return CreateFileA(DEVICENAME, GENERIC_READ | GENERIC_WRITE | FILE_GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, 0);
}

bool DriverMapMemory(HANDLE hDriver, IoCommand* myIo) {
	DWORD read = 0;
	return DeviceIoControl(hDriver, IOCTL_MAPMEMORY, myIo, sizeof(*myIo), myIo, sizeof(*myIo), &read, 0);

}
bool DriverUnmapMemory(HANDLE hDriver, IoCommand* myIo) {
	DWORD read = 0;
	return DeviceIoControl(hDriver, IOCTL_UNMAPMEM, myIo, sizeof(*myIo), myIo, sizeof(*myIo), &read, 0);
}

bool CloseDriver(HANDLE hDriver) {
	return CloseHandle(hDriver);
}