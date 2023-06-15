#include "funcs.h"


int CompareUnicodeStrings(WCHAR substring[], WCHAR bigstring[]) {

	_wcslwr_s(substring, MAX_PATH);
	_wcslwr_s(bigstring, MAX_PATH);
	WCHAR* str1 = wcsrchr(bigstring, L'\\');
	WCHAR s_to_cmp[MAX_PATH];
	if (str1 == NULL) {
		wcscpy_s(s_to_cmp, bigstring);
	} else { wcscpy_s(s_to_cmp, str1 + 1); }
	
	int result = 0;
	if (!wcscmp(s_to_cmp, substring)){
		result = 1;
	}

	return result;
}


HMODULE WINAPI pGetModuleHandle(const wchar_t* sModuleName) {
	// get peb ptr
	//wchar_t pathModuleName[MAX_PATH] = L"C:\\WINDOWS\\System32\\";
	//wcscat_s(pathModuleName, sModuleName);

	PEB* peb = (PEB*)__readgsqword(0x60);
	PEB_LDR_DATA* ldr = peb->Ldr;
	LIST_ENTRY* mod_list = &ldr->InMemoryOrderModuleList;

	LIST_ENTRY* list_start = mod_list->Flink;

	WCHAR str1[MAX_PATH] = { 0 };
	WCHAR str2[MAX_PATH] = { 0 };

	for (LIST_ENTRY* list_ptr = list_start; list_ptr != mod_list; list_ptr = list_ptr->Flink) {

		LDR_DATA_TABLE_ENTRY* ldr_entry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)list_ptr - sizeof(LIST_ENTRY));
		// Checking if this is the DLL we are looking for
		memset(str1, 0, MAX_PATH * sizeof(WCHAR));
		memset(str2, 0, MAX_PATH * sizeof(WCHAR));
		wcscpy_s(str2, MAX_PATH, ldr_entry->FullDllName.Buffer);
		wcscpy_s(str1, MAX_PATH, sModuleName);
		if (CompareUnicodeStrings(str1, str2)){
			// Returning the DLL base address.
			printf("\nGET_MODULE_HANDLE CALL\n--------------------\n[*] Base Address: %p\n|*\n[*] DLL Name: %ls\n--------------------\n\n", ldr_entry->DllBase, ldr_entry->FullDllName.Buffer);
			
			return (HMODULE)ldr_entry->DllBase;
		}
	}

	// The needed DLL wasn't found
	printf("\nHMODULE wasn't found!");
	return NULL;
}

FARPROC WINAPI pGetProcAddress(HMODULE hMod, char* sProcName) {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)(char*)hMod;	// could be source of issue!!
	char* base_address = (char*)dos_header;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(dos_header->e_lfanew + base_address);
	IMAGE_OPTIONAL_HEADER64* opt_header = &nt_header->OptionalHeader;

	IMAGE_DATA_DIRECTORY* exp_addr = (IMAGE_DATA_DIRECTORY*)&opt_header->DataDirectory[0];	// export rva
	IMAGE_EXPORT_DIRECTORY* exp_dat = (IMAGE_EXPORT_DIRECTORY*)(exp_addr->VirtualAddress + base_address); // exp data va
	
	DWORD* EAT = (DWORD*)(exp_dat->AddressOfFunctions + base_address);				// addy of functions array VA
	DWORD* names = (DWORD*)(exp_dat->AddressOfNames + base_address);				// addy of names array VA
	WORD* ordinals = (WORD*)(exp_dat->AddressOfNameOrdinals + base_address);		// addy of ordinals array VA
	DWORD num_names = exp_dat->NumberOfNames;

	void* proc_addr = 0;

	for (int i = 0; i < (int)num_names; i++) {
		char* procName = names[i] + base_address;
		if (!strcmp(sProcName, (names[i]) + base_address)) {
			proc_addr = (FARPROC)(EAT[ordinals[i]] + base_address);
			break;
		}
	}
	if (!proc_addr) { return NULL; }
	if (strchr((char*)proc_addr, '.')){
		char* sFwdDLL = _strdup((char*)proc_addr);
		if (!sFwdDLL) return NULL;

		// Parse the {DLL Name}.{Function name}, when the '.' is the delimiter. 
		char* sFwdFunction = strchr(sFwdDLL, '.');
		*sFwdFunction = 0;
		sFwdFunction++;
		// Create a CallBack to LoadLibraryA, so we can later use it to load the external DLL into our process
		UCANTFINDME_LOADLIB pLoadLibraryA = NULL;
		pLoadLibraryA = (UCANTFINDME_LOADLIB)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"LoadLibraryA");

		// load the DLL
		HMODULE hFwd = pLoadLibraryA(sFwdDLL);
		free(sFwdDLL);
		if (!hFwd)
			return NULL;

		//recursivly calling our implementation of GetProcAddress, passing the new HMODULE and function name. 
		proc_addr = pGetProcAddress(hFwd, sFwdFunction);
	}
	printf("\nGET_PROC_ADDRESS CALL\n--------------------\n[*] Process Address: %p\n|*\n[*] Function Name: %s\n--------------------\n\n", proc_addr, sProcName);
	return (FARPROC)proc_addr;

}

