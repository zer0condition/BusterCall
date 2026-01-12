#include "service.h"

static SC_HANDLE g_DriverService = nullptr;
static HKEY      g_DriverKey     = nullptr;

bool service::Load()
{
	loader::OpenScm();

	const auto DriverPath = std::string("\\SystemRoot\\System32\\drivers\\AsusBiosIoDrv64.sys");

	g_DriverService = loader::CreateService(
		"AsusBiosIoDrv64",
		"",
		DriverPath
	);

	if (!g_DriverService)
		return false;

	bool Success = loader::StartService(g_DriverService);

	if (!Success) 
	{
		RegCloseKey(g_DriverKey);
		loader::DeleteService(g_DriverService);
	}

	return Success;
}

void service::Cleanup()
{
	if (g_DriverKey)
		RegCloseKey(g_DriverKey);

	if (g_DriverService)
	{
		SERVICE_STATUS ServiceStatus{};
		loader::StopService(g_DriverService, &ServiceStatus);
		loader::DeleteService(g_DriverService);
		CloseServiceHandle(g_DriverService);
	}

	loader::CloseScm();
}

bool service::Drop()
{
	HANDLE FileHandle;
	BOOLEAN Status = FALSE;
	DWORD BytesWritten = 0;

	FileHandle = CreateFileW(
		L"C:\\Windows\\System32\\drivers\\AsusBiosIoDrv64.sys", 
		GENERIC_ALL, 
		NULL, 
		NULL, 
		CREATE_NEW, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL
	);

	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (FileHandle == INVALID_HANDLE_VALUE)
		return false;

	Status = WriteFile(FileHandle, AsusBiosIoDrv64, sizeof(AsusBiosIoDrv64), &BytesWritten, nullptr);
	CloseHandle(FileHandle);

	if (!Status)
		return false;

	return true;
}

bool service::Remove()
{
	DeleteFile(L"C:\\Windows\\System32\\drivers\\AsusBiosIoDrv64.sys");
	return true;
}