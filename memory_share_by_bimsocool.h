#pragma once
#include <Windows.h>
#include <vector>
#include <string> 
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>


class Memory
{

public:

	const char* GetEmulatorRunning()
	{
		if (GetPid("HD-Player.exe") != 0)
			return "HD-Player.exe";

		else if (GetPid("MEmuHeadless.exe") != 0)
			return "MEmuHeadless.exe";

		else if (GetPid("LdVBoxHeadless.exe") != 0)
			return "LdVBoxHeadless.exe";

		else if (GetPid("AndroidProcess.exe") != 0)
			return "AndroidProcess.exe";

		else if (GetPid("Nox.exe") != 0)
			return "Nox.exe";
	}

	void ReWrite(std::string type, DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* Search, BYTE* Replace)
	{
		if (!AttackProcess(GetEmulatorRunning()))
			//error 
			error_notify = true;
		Sleep(20);

		bool Status = ReplacePattern(dwStartRange, dwEndRange, Search, Replace, true);
		if (Status)
			//aplicado
			active_notify = true;
		else
			//error al aplicar
			error_notify = true;


		CloseHandle(ProcessHandle);
	}

	


	void Example()
	{
		if (!AttackProcess(GetEmulatorRunning()))
			error_notify = true;

		bool st = ReplacePattern(0x0L, 0x00007fffffffffff,
			new BYTE[]{ 0xED, 0xF0, 0x54, 0xFD, 0x18, 0xE1, 0xD9, 0xF8, 0x00, 0x00, 0xD9, 0xF8, 0x04, 0x10 },
			new BYTE[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0xE3 }, true);

		bool st2 = ReplacePattern(0x0L, 0x00007fffffffffff,
			new BYTE[]{ 0xF0, 0xB5, 0x03, 0xAF, 0x2D, 0xE9, 0x00, 0x07, 0xAD, 0xF5, 0x82, 0x6D},
			new BYTE[]{ 0x00, 0x29, 0x70, 0x47, 0x00, 0x00, 0xA0, 0xE3 }, true);


		if (st2) {
			
		}
		else {
			
		}
			

		CloseHandle(ProcessHandle);
	}

	

	DWORD ProcessId = 0;
	HANDLE ProcessHandle;

	typedef struct _MEMORY_REGION
	{
		DWORD_PTR dwBaseAddr;
		DWORD_PTR dwMemorySize;
	}

	MEMORY_REGION;

	int GetPid(const char* procname) {

		if (procname == NULL)
			return 0;
		DWORD pid = 0;
		DWORD threadCount = 0;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe;

		pe.dwSize = sizeof(PROCESSENTRY32);
		Process32First(hSnap, &pe);
		while (Process32Next(hSnap, &pe)) {
			if (_tcsicmp(pe.szExeFile, procname) == 0) {
				if ((int)pe.cntThreads > threadCount) {
					threadCount = pe.cntThreads;

					pid = pe.th32ProcessID;

				}
			}
		}
		return pid;
	}

	BOOL AttackProcess(const char* procname)
	{
		DWORD ProcId = GetPid(procname);
		if (ProcId == 0)
			return false;

		ProcessId = ProcId;
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
		return ProcessHandle != nullptr;
	}

	bool ChangeProtection(ULONG Address, size_t size, DWORD NewProtect, DWORD& OldProtect)
	{
		return VirtualProtectEx(ProcessHandle, (LPVOID)Address, size, NewProtect, &OldProtect);;
	}

	bool ReplacePattern(DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* SearchAob, BYTE* ReplaceAob, bool ForceWrite = false)
	{
		int RepByteSize = _msize(ReplaceAob);
		if (RepByteSize <= 0) return false;
		std::vector<DWORD_PTR> foundedAddress;
		FindPattern(dwStartRange, dwEndRange, SearchAob, foundedAddress);
		if (foundedAddress.empty())
			return false;

		OutputDebugStringA(std::to_string(foundedAddress.size()).c_str());

		DWORD OldProtect;
		for (int i = 0; i < foundedAddress.size(); i++)
		{
			ChangeProtection(foundedAddress[i], RepByteSize, PAGE_EXECUTE_READWRITE, OldProtect);
			WriteProcessMemory(ProcessHandle, (LPVOID)foundedAddress[i], ReplaceAob, RepByteSize, 0);
		}

		return true;
	}


	bool FindPattern(DWORD_PTR StartRange, DWORD_PTR EndRange, BYTE* SearchBytes, std::vector<DWORD_PTR>& AddressRet)
	{

		BYTE* pCurrMemoryData = NULL;
		MEMORY_BASIC_INFORMATION	mbi;
		std::vector<MEMORY_REGION> m_vMemoryRegion;
		mbi.RegionSize = 0x1000;
		DWORD_PTR dwAddress = StartRange;
		DWORD_PTR nSearchSize = _msize(SearchBytes);


		while (VirtualQueryEx(ProcessHandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < EndRange) && ((dwAddress + mbi.RegionSize) > dwAddress))
		{
			if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
			{

				MEMORY_REGION mData = { 0 };
				mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
				mData.dwMemorySize = mbi.RegionSize;
				m_vMemoryRegion.push_back(mData);

			}
			dwAddress = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
		}

		std::vector<MEMORY_REGION>::iterator it;
		for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
		{
			MEMORY_REGION mData = *it;


			DWORD_PTR dwNumberOfBytesRead = 0;
			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(ProcessHandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);
			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
			DWORD_PTR dwOffset = 0;
			int iOffset = Memfind(pCurrMemoryData, dwNumberOfBytesRead, SearchBytes, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				AddressRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = Memfind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, SearchBytes, nSearchSize);
			}

			if (pCurrMemoryData != NULL)
			{
				delete[] pCurrMemoryData;
				pCurrMemoryData = NULL;
			}

		}
		return TRUE;
	}

	int Memfind(BYTE* buffer, DWORD_PTR dwBufferSize, BYTE* bstr, DWORD_PTR dwStrLen) {
		if (dwBufferSize < 0)
		{
			return -1;
		}
		DWORD_PTR  i, j;
		for (i = 0; i < dwBufferSize; i++) {
			for (j = 0; j < dwStrLen; j++) {
				if (buffer[i + j] != bstr[j] && bstr[j] != '?')
					break;
			}
			if (j == dwStrLen)
				return i;
		}
		return -1;
	}
};