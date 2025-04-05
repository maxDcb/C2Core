#include "peb.hpp"


#if _WIN32


// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)


// find a DLL with a certain export, used by xGetProcAddress and FindExport
LPVOID find_reference(
    IN LPVOID original_dll,
    IN PCHAR dll_name,
    IN PCHAR api_name)
{
    PPEB2                  peb  = NULL;
    PPEB_LDR_DATA2         ldr  = NULL;
    PLDR_DATA_TABLE_ENTRY2 dte  = NULL;
    LPVOID                 addr = NULL;
    LPVOID                 base = NULL;

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ldr = (PPEB_LDR_DATA2)peb->Ldr;

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY2)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY2)dte->InLoadOrderLinks.Flink)
    {
        base = dte->DllBase;
        // if this is the dll with the reference, continue
        if (base == original_dll) continue;

        addr = xGetProcAddress(base, api_name, 0);
    }
    if (addr == NULL)
    {
        // we did not find the reference, use LoadLibrary
        // DPRINT("Could not find %s, using LoadLibraryA", dll_name);
        HMODULE hModule = LoadLibraryA(dll_name);
        if (hModule != NULL)
        {
            // DPRINT("Calling GetProcAddress(%s, %s)", dll_name, api_name);
            addr = GetProcAddress(hModule, api_name);
        }
    }

    return addr;
}


// size_t StringLengthA(const char* str) 
// {
//     if (str == nullptr) 
//         return 0;

//     size_t length = 0;
//     while (str[length] != '\0') 
//     {
//         ++length;
//     }
//     return length;
// }


// search for an export in a DLL
LPVOID xGetProcAddress(
    IN LPVOID base,
    IN PCHAR api_name,
    IN DWORD ordinal)
{
    PIMAGE_DOS_HEADER       dos           = NULL;
    PIMAGE_NT_HEADERS       nt            = NULL;
    PIMAGE_DATA_DIRECTORY   dir           = NULL;
    PIMAGE_EXPORT_DIRECTORY exp           = NULL;
    LPVOID                  addr          = NULL;
    DWORD                   rva           = 0;
    DWORD                   cnt           = 0;
    PDWORD                  adr           = NULL;
    PDWORD                  sym           = NULL;
    PWORD                   ord           = NULL;
    PCHAR                   api           = NULL;
    CHAR                    dll_name[256] = { 0 };
    CHAR                    new_api[256]  = { 0 };
    DWORD                   i             = 0;
    PCHAR                   p             = NULL;
    DWORD                   len           = 0;
    PVOID                   newbase       = NULL;

    if (base == NULL) return NULL;

    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // if no export table, return NULL
    if (rva == 0) return NULL;

    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

    if (api_name != NULL)
    {
        // exported by name
        cnt = exp->NumberOfNames;
        // if no api names, return NULL
        if (cnt == 0) return NULL;

        do {
            api = RVA2VA(PCHAR, base, sym[cnt-1]);
            // check if the export name matches the API we are looking for
            if (!_stricmp(api, api_name))
            {
                // get the address of the API
                addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
            }
        } while (--cnt && addr == NULL);
    }
    else
    {
        // exported by ordinal
        addr = RVA2VA(PVOID, base, adr[ordinal - exp->Base]);
    }

    //   // is this a forward reference?
    // if ((PBYTE)addr >= (PBYTE)exp &&
    //   (PBYTE)addr <  (PBYTE)exp +
    //   dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
    // {
    //     //DPRINT("%s is forwarded to %s", api_name, (char*)addr);

    //     // copy DLL name to buffer
    //     p=(char*)addr;
    //     len=StringLengthA(p);

    //     for (i=0; p[i] != 0 && i < sizeof(dll_name) - 4; i++)
    //     {
    //         dll_name[i] = p[i];
    //     }

    //     for (i=len-1; i > 0; i--)
    //     {
    //         if(p[i] == '.') break;
    //     }

    //     dll_name[i+1] = 'd';
    //     dll_name[i+2] = 'l';
    //     dll_name[i+3] = 'l';
    //     dll_name[i+4] = 0;

    //     p += i + 1;

    //     // copy API name to buffer
    //     for(i = 0; p[i] != 0 && i < sizeof(new_api) - 1; i++)
    //     {
    //         new_api[i] = p[i];
    //     }
    //     new_api[i] = 0;

    //     newbase = handle_dependency(NULL, dll_name);
    //     if (base == newbase)
    //     {
    //         /*
    //          * the api set seems to resolve to itself...
    //          * lets just iterate over all loaded modules and
    //          * find a module with the export we are looking for
    //          */
            
    //         addr = find_reference(base, dll_name, new_api);
    //     }
    //     else
    //     {
    //         /*
    //          * we got a different DLL, call xGetProcAddress recursively
    //          */

    //         addr = xGetProcAddress(newbase, new_api, 0);
    //     }
    // }

    return addr;
}


// find a DLL by name, load it if not found
LPVOID xGetLibAddress(
    IN PCHAR search,
    IN BOOL load,
    OUT PBOOL loaded)
{
    PPEB2                   peb          = NULL;
    PPEB_LDR_DATA2          ldr          = NULL;
    PIMAGE_DOS_HEADER       dos          = NULL;
    PIMAGE_NT_HEADERS       nt           = NULL;
    PLDR_DATA_TABLE_ENTRY2  dte          = NULL;
    PIMAGE_EXPORT_DIRECTORY exp          = NULL;
    LPVOID                  addr         = NULL;
    LPVOID                  base         = NULL;
    DWORD                   rva          = 0;
    PCHAR                   name         = NULL;
    CHAR                    dll_name[64] = { 0 };
    DWORD                   i            = 0;
    int                     correct      = -1;

    if (loaded)
        *loaded = FALSE;

    for(i = 0; search[i] != 0 && i < 64; i++)
    {
        dll_name[i] = search[i];
    }
    dll_name[i] = 0;
    // make sure the name ends with '.dll'
    if (dll_name[i-4] != '.')
    {
        dll_name[i++] = '.';
        dll_name[i++] = 'd';
        dll_name[i++] = 'l';
        dll_name[i++] = 'l';
        dll_name[i++] = 0;
    }

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ldr = (PPEB_LDR_DATA2)peb->Ldr;

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY2)ldr->InLoadOrderModuleList.Flink;
         correct != 0 && dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY2)dte->InLoadOrderLinks.Flink)
    {
        base = dte->DllBase;
        dos  = (PIMAGE_DOS_HEADER)base;
        nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
        rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (rva == 0) continue;

        exp  = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
        name = RVA2VA(PCHAR, base, exp->Name);

        correct = _stricmp(dll_name, name);

        if (correct == 0) {
            addr = base;
        }
    }

    //DPRINT("Address of %s: %p", dll_name, addr);

    // if the DLL was not found, load it
    if (!addr && load)
    {
        addr = LoadLibraryA(dll_name);
        // DPRINT("Dll not found. Loaded %s via LoadLibrary at 0x%p", dll_name, addr);
        if (addr && loaded)
            *loaded = TRUE;
    }

    return addr;
}


#endif