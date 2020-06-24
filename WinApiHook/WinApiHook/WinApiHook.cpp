#pragma once 

/******************************************************************************
Module:  APIHook.cpp
Notices: Copyright (c) 2008 Jeffrey Richter & Christophe Nasarre
******************************************************************************/

#include <Windows.h>
#include <ImageHlp.h>
#include <stdio.h>

#pragma comment(lib, "ImageHlp")

#define CRTDLL "UCRTBASED.DLL"

typedef FILE* (_cdecl* MyFileOpen) (const char* path, const char* mode);

void ReplaceIATEntryInOneMod(PCSTR pszCalleeModName,
	MyFileOpen pfnCurrent, MyFileOpen pfnNew, HMODULE hmodCaller);

static MyFileOpen myFileOpen;

FILE* _cdecl myFopen(const char* path, const char* mode)
{
	printf("myFopen\n");

	return myFileOpen(path, mode);
}

void InitWinApiHook()
{
	myFileOpen = (MyFileOpen)GetProcAddress(GetModuleHandle(CRTDLL), "fopen");

	HMODULE hMod = GetModuleHandle("WinApiHook.exe");

	ReplaceIATEntryInOneMod(CRTDLL, myFileOpen, myFopen, hMod);
}

LONG WINAPI InvalidReadExceptionFilter(PEXCEPTION_POINTERS pep) {

	// handle all unexpected exceptions because we simply don't patch
	// any module in that case
	LONG lDisposition = EXCEPTION_EXECUTE_HANDLER;

	// Note: pep->ExceptionRecord->ExceptionCode has 0xc0000005 as a value

	return(lDisposition);
}

void ReplaceIATEntryInOneMod(PCSTR pszCalleeModName,
	MyFileOpen pfnCurrent, MyFileOpen pfnNew, HMODULE hmodCaller) {

	// Get the address of the module's import section
	ULONG ulSize;

	// An exception was triggered by Explorer (when browsing the content of 
	// a folder) into imagehlp.dll. It looks like one module was unloaded...
	// Maybe some threading problem: the list of modules from Toolhelp might 
	// not be accurate if FreeLibrary is called during the enumeration.
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
	__try {
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
			hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
	}
	__except (InvalidReadExceptionFilter(GetExceptionInformation())) {
		// Nothing to do in here, thread continues to run normally
		// with NULL for pImportDesc 
	}

	if (pImportDesc == NULL)
		return;  // This module has no import section or is no longer loaded


	 // Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) {
		PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);
		if (lstrcmpiA(pszModName, pszCalleeModName) == 0) {

			// Get caller's import address table (IAT) for the callee's functions
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
				((PBYTE)hmodCaller + pImportDesc->FirstThunk);

			// Replace current function address with new function address
			for (; pThunk->u1.Function; pThunk++) {

				// Get the address of the function address
				MyFileOpen* ppfn = (MyFileOpen*)&pThunk->u1.Function;

				// Is this the function we're looking for?
				BOOL bFound = (*ppfn == pfnCurrent);
				if (bFound) {
					if (!WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
						sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError())) {
						DWORD dwOldProtect;
						if (VirtualProtect(ppfn, sizeof(pfnNew), PAGE_WRITECOPY,
							&dwOldProtect)) {

							WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
								sizeof(pfnNew), NULL);
							VirtualProtect(ppfn, sizeof(pfnNew), dwOldProtect,
								&dwOldProtect);
						}
					}
					return;  // We did it, get out
				}
			}
		}  // Each import section is parsed until the right entry is found and patched
	}
}