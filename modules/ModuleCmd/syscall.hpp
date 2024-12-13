#include <windows.h>
#include <tlhelp32.h>
#include "include.hpp"

#include <vector>
#include <algorithm>


DWORD SW3_HashSyscall(PCSTR FunctionName);
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash);


EXTERN_C NTSTATUS Sw3NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);


EXTERN_C NTSTATUS Sw3NtWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);


EXTERN_C NTSTATUS Sw3NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);


EXTERN_C NTSTATUS Sw3NtClose(
	IN HANDLE Handle);


EXTERN_C NTSTATUS Sw3NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


EXTERN_C NTSTATUS Sw3NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);


EXTERN_C NTSTATUS Sw3NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);


EXTERN_C NTSTATUS Sw3NtCreateProcess(
  OUT PHANDLE           ProcessHandle,
  IN ACCESS_MASK        DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
  IN HANDLE             ParentProcess,
  IN BOOLEAN            InheritObjectTable,
  IN HANDLE             SectionHandle OPTIONAL,
  IN HANDLE             DebugPort OPTIONAL,
  IN HANDLE             ExceptionPort OPTIONAL ); 


EXTERN_C NTSTATUS Sw3NtQueueApcThread(
  IN HANDLE               ThreadHandle,
  IN PIO_APC_ROUTINE      ApcRoutine,
  IN PVOID                ApcRoutineContext OPTIONAL,
  IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
  IN ULONG                ApcReserved OPTIONAL );


EXTERN_C NTSTATUS Sw3NtResumeThread(
  IN HANDLE               ThreadHandle,
  OUT PULONG              SuspendCount OPTIONAL );


DWORD GlobalHash = 0x0;


EXTERN_C DWORD getGlobalHash()
{
	return GlobalHash;
}


void XOR(char * data, size_t data_len, char * key, size_t key_len) 
{
	int j = 0;
	for (int i = 0; i < data_len; i++) 
	{
		if (j == key_len-1) 
			j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
	
	data[data_len-1]='\0';
}


DWORD SW3_HashSyscall(const char *FunctionName)
{
    DWORD Hash = 0x811C9DC5; // FNV offset basis
    DWORD FNV_prime = 0x01000193; // FNV prime

    int c;
    while (c = *FunctionName++) 
	{
        Hash ^= c;                 // XOR the byte into the lowest byte of the hash
        Hash *= FNV_prime;          // Multiply by FNV prime
    }

    return Hash & 0xFFFFFFFF;       // Ensure the result is a 32-bit hash
}


NTSTATUS Sw3NtAllocateVirtualMemory_(
HANDLE ProcessHandle,
PVOID * BaseAddress,
ULONG ZeroBits,
PSIZE_T RegionSize,
ULONG AllocationType,
ULONG Protect)
{
	// need to put Zw for the syscall
	// char *FunctionName = "ZwAllocateVirtualMemory";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwAllocateVirtualMemory " << GlobalHash << std::endl;

	GlobalHash = 806327511;

	return Sw3NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}


NTSTATUS Sw3NtWaitForSingleObject_(
HANDLE ObjectHandle,
BOOLEAN Alertable,
PLARGE_INTEGER TimeOut)
{
	// char *FunctionName = "ZwWaitForSingleObject";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwWaitForSingleObject " << GlobalHash << std::endl;

	GlobalHash = 3941435821;

	return Sw3NtWaitForSingleObject(ObjectHandle, Alertable, TimeOut);
}


NTSTATUS Sw3NtClose_(
HANDLE Handle)
{
// 	char *FunctionName = "ZwClose";
// 	GlobalHash = SW3_HashSyscall(FunctionName);
// std::cout << "ZwClose " << GlobalHash << std::endl;

	GlobalHash = 745328858;

	return Sw3NtClose(Handle);
}


NTSTATUS Sw3NtWriteVirtualMemory_(
HANDLE ProcessHandle,
PVOID BaseAddress,
PVOID Buffer,
SIZE_T NumberOfBytesToWrite,
PSIZE_T NumberOfBytesWritten )
{
	// char *FunctionName = "ZwWriteVirtualMemory";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwWriteVirtualMemory " << GlobalHash << std::endl;

	GlobalHash = 4080026747;

	return Sw3NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}


NTSTATUS Sw3NtProtectVirtualMemory_(
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect)
{
	// char *FunctionName = "ZwProtectVirtualMemory";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwProtectVirtualMemory " << GlobalHash << std::endl;

	GlobalHash = 699580991;

	return Sw3NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}


// fail if we put the has calculation in this function !!
NTSTATUS Sw3NtOpenProcess_(
PHANDLE ProcessHandle,
ACCESS_MASK DesiredAccess,
POBJECT_ATTRIBUTES ObjectAttributes,
PCLIENT_ID ClientId)
{
	// char *FunctionName = "ZwOpenProcess";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwAllocateVirtualMemory " << GlobalHash << std::endl;

	GlobalHash = 3548847587;

	// __debugbreak();
	return Sw3NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

}


NTSTATUS Sw3NtCreateThreadEx_(
PHANDLE ThreadHandle,
ACCESS_MASK DesiredAccess,
POBJECT_ATTRIBUTES ObjectAttributes,
HANDLE ProcessHandle,
PVOID StartRoutine,
PVOID Argument,
ULONG CreateFlags,
SIZE_T ZeroBits,
SIZE_T StackSize,
SIZE_T MaximumStackSize,
PPS_ATTRIBUTE_LIST AttributeList)
{
	// char *FunctionName = "ZwCreateThreadEx";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwCreateThreadEx " << GlobalHash << std::endl;

	GlobalHash = 3653557611;

	return Sw3NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}


NTSTATUS Sw3NtCreateProcess_(
PHANDLE ProcessHandle,
ACCESS_MASK DesiredAccess,
POBJECT_ATTRIBUTES ObjectAttributes,
HANDLE ParentProcess,
BOOLEAN InheritObjectTable,
HANDLE SectionHandle,
HANDLE DebugPort,
HANDLE ExceptionPort)
{
	// PCSTR FunctionName = "ZwCreateProcess";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwCreateProcess " << GlobalHash << std::endl;

	// TODO get the has
	// GlobalHash = 3653557611;

	return Sw3NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}


EXTERN_C NTSTATUS Sw3NtQueueApcThread_(
HANDLE               ThreadHandle,
PIO_APC_ROUTINE      ApcRoutine,
PVOID                ApcRoutineContext,
PIO_STATUS_BLOCK     ApcStatusBlock,
ULONG                ApcReserved)
{
	// PCSTR FunctionName = "ZwQueueApcThread";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwQueueApcThread " << GlobalHash << std::endl;

	GlobalHash = 735850453;

	return Sw3NtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
}


EXTERN_C NTSTATUS Sw3NtResumeThread_(
HANDLE ThreadHandle,
PULONG SuspendCount)
{
	// PCSTR FunctionName = "ZwResumeThread";
	// GlobalHash = SW3_HashSyscall(FunctionName);
	// std::cout << "ZwResumeThread " << GlobalHash << std::endl;

	GlobalHash = 4130550557;

	return Sw3NtResumeThread(ThreadHandle, SuspendCount);
}


class Entry
{
public:
	Entry(DWORD hash, DWORD address, PVOID syscallAddress)
	: m_hash(hash)
	, m_address(address)
	, m_syscallAddress(syscallAddress)
	{
	}

	DWORD getHash()
	{
		return m_hash;
	}

	DWORD getAddress()
	{
		return m_address;
	}

	PVOID getSyscallAddress()
	{
		return m_syscallAddress;
	}


private:
    DWORD m_hash;
    DWORD m_address;
	PVOID m_syscallAddress;
};


bool compareEntry(Entry i1, Entry i2) 
{ 
    return (i1.getAddress() < i2.getAddress()); 
} 


class SyscallList
{
private:

	PVOID getNtdllExportDirectory()
	{
		PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);

		PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
		m_dllBase = NULL;

		// Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
		// in the list, so it's safer to loop through the full list and find it.
		PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
		for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
		{
			m_dllBase = LdrEntry->DllBase;
			PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)m_dllBase;
			PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, m_dllBase, DosHeader->e_lfanew);
			PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
			DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (VirtualAddress == 0) continue;

			ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, m_dllBase, VirtualAddress);

			// If this is NTDLL.dll, exit loop.
			PCHAR DllName = SW3_RVA2VA(PCHAR, m_dllBase, ExportDirectory->Name);

			if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) 
				continue;
			if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) 
				break;
		}

		if (!ExportDirectory) 
			return NULL;

		return (PVOID)ExportDirectory;
	}

	void fillSyscallEntryList(PVOID add)
	{
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)add;
		DWORD NumberOfNames = ExportDirectory->NumberOfNames;
		PDWORD Functions = SW3_RVA2VA(PDWORD, m_dllBase, ExportDirectory->AddressOfFunctions);
		PDWORD Names = SW3_RVA2VA(PDWORD, m_dllBase, ExportDirectory->AddressOfNames);
		PWORD Ordinals = SW3_RVA2VA(PWORD, m_dllBase, ExportDirectory->AddressOfNameOrdinals);

		// Populate SW3_SyscallList with unsorted Zw* entries.
		do
		{
			PCHAR FunctionName = SW3_RVA2VA(PCHAR, m_dllBase, Names[NumberOfNames - 1]);

			// Is this a system call?
			// start with Zw
			if (*(USHORT*)FunctionName == 0x775a)
			{
				DWORD Hash = SW3_HashSyscall(FunctionName);

				DWORD Address = Functions[Ordinals[NumberOfNames - 1]];
				PVOID SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, m_dllBase, Address));

				Entry newEntry(Hash, Address, SyscallAddress);
				m_syscallEntry.push_back(std::move(newEntry));

			}
		} while (--NumberOfNames);

		// sort for the getSyscallNumber
		std::sort(m_syscallEntry.begin(), m_syscallEntry.end(), compareEntry); 
	}

	
	PVOID SC_Address(PVOID NtApiAddress)
	{
		DWORD searchLimit = 512;
		PVOID SyscallAddress;

		// If the process is 64-bit on a 64-bit OS, we need to search for syscall
		BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
		ULONG distance_to_syscall = 0x12;

		// we don't really care if there is a 'jmp' between
		// NtApiAddress and the 'syscall; ret' instructions
		SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			// we can use the original code for this system call :)
			return SyscallAddress;
		}

		// the 'syscall; ret' intructions have not been found,
		// we will try to use one near it, similarly to HalosGate
		for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
		{
			// let's try with an Nt* API below our syscall
			SyscallAddress = SW3_RVA2VA(
				PVOID,
				NtApiAddress,
				distance_to_syscall + num_jumps * 0x20);

			if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
			{
				return SyscallAddress;
			}

			// let's try with an Nt* API above our syscall
			SyscallAddress = SW3_RVA2VA(
				PVOID,
				NtApiAddress,
				distance_to_syscall - num_jumps * 0x20);

			if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
			{
				return SyscallAddress;
			}
		}

		return NULL;
	}

	PVOID m_dllBase;
	std::vector<Entry> m_syscallEntry;

protected:
    SyscallList()
    {
		PVOID add = getNtdllExportDirectory();
		fillSyscallEntryList(add);
    }

    static SyscallList* singleton_;

public:

    SyscallList(SyscallList &other) = delete;
    void operator=(const SyscallList &) = delete;
    static SyscallList *GetInstance();

	// need to be sorted to be able to get the syscall number from the entry index
    DWORD getSyscallNumber(DWORD hash)
    {
		for(int i=0; i<m_syscallEntry.size(); i++)
		{
			if(m_syscallEntry[i].getHash() == hash)
			{
				return i;
			}
		}
        return -1;
    }

	PVOID getSyscallAddress(DWORD hash)
    {
        for(int i=0; i<m_syscallEntry.size(); i++)
		{
			if(m_syscallEntry[i].getHash() == hash)
			{
				return m_syscallEntry[i].getSyscallAddress();
			}
		}
        return NULL;
    }
};


SyscallList* SyscallList::singleton_= nullptr;


SyscallList *SyscallList::GetInstance()
{
    if(singleton_==nullptr){
        singleton_ = new SyscallList();
    }
    return singleton_;
}


EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	SyscallList* singleton = SyscallList::GetInstance();
	return singleton->getSyscallNumber(FunctionHash);
}


EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
	SyscallList* singleton = SyscallList::GetInstance();
	return singleton->getSyscallAddress(FunctionHash);
}

