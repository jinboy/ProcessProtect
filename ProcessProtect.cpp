// ProcessProtect.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

/*


*/
int _tmain(int argc, _TCHAR* argv[])
{



	return 0;
}

#ifndef CXX_PROTECTPROCESSX64_H
#define CXX_PROTECTPROCESSX64_H

#include <ntifs.h>

#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020  

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

extern
UCHAR *
PsGetProcessImageFileName(
__in PEPROCESS Process
);
char*
GetProcessImageNameByProcessID(ULONG ulProcessID);

NTSTATUS ProtectProcess(BOOLEAN Enable);

OB_PREOP_CALLBACK_STATUS
preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

#endif    







#ifndef CXX_PROTECTPROCESSX64_H
#    include "ProtectProcessx64.h"
#endif


PVOID obHandle;//����һ��void*���͵ı�������������ΪObRegisterCallbacks�����ĵڶ���������

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY64 ldr;

	pDriverObj->DriverUnload = DriverUnload;
	// �ƹ�MmVerifyCallbackFunction��
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;

	ProtectProcess(TRUE);

	return STATUS_SUCCESS;
}



NTSTATUS ProtectProcess(BOOLEAN Enable)
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	memset(&opReg, 0, sizeof(opReg)); //��ʼ���ṹ�����

	//������ע������ṹ��ĳ�Ա�ֶε�����
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall; //������ע��һ���ص�����ָ��

	obReg.OperationRegistration = &opReg; //ע����һ�����

	return ObRegisterCallbacks(&obReg, &obHandle); //������ע��ص�����
}


OB_PREOP_CALLBACK_STATUS
preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	char szProcName[16] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	strcpy(szProcName, GetProcessImageNameByProcessID((ULONG)pid));
	if (!_stricmp(szProcName, "calc.exe"))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				//Terminate the process, such as by calling the user-mode TerminateProcess routine..
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}


/*
OpenProcess ��һֱ����ص���  ֱ������
char*
GetProcessImageNameByProcessID(ULONG ulProcessID)
{
CLIENT_ID Cid;
HANDLE    hProcess;
NTSTATUS  Status;
OBJECT_ATTRIBUTES  oa;
PEPROCESS  EProcess = NULL;

Cid.UniqueProcess = (HANDLE)ulProcessID;
Cid.UniqueThread = 0;

InitializeObjectAttributes(&oa,0,0,0,0);
Status = ZwOpenProcess(&hProcess,PROCESS_ALL_ACCESS,&oa,&Cid);    //hProcess
//ǿ�򿪽��̻�þ��
if (!NT_SUCCESS(Status))
{
return FALSE;
}
Status = ObReferenceObjectByHandle(hProcess,FILE_READ_DATA,0,
KernelMode,&EProcess, 0);
//ͨ���������ȡEProcess
if (!NT_SUCCESS(Status))
{
ZwClose(hProcess);
return FALSE;
}
ObDereferenceObject(EProcess);
//����ж�
ZwClose(hProcess);
//ͨ��EProcess��ý�������
return (char*)PsGetProcessImageFileName(EProcess);

}
*/




char*
GetProcessImageNameByProcessID(ULONG ulProcessID)
{
	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;


	Status = PsLookupProcessByProcessId((HANDLE)ulProcessID, &EProcess);    //EPROCESS

	//ͨ�������ȡEProcess
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	//ͨ��EProcess��ý�������
	return (char*)PsGetProcessImageFileName(EProcess);

}



VOID
DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	DbgPrint("driver unloading...\n");

	ObUnRegisterCallbacks(obHandle); //obHandle�����涨��� PVOID obHandle;
}

