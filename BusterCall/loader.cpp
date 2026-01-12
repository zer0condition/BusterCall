#include "loader.h"

static SC_HANDLE g_ScmHandle = nullptr;

bool loader::OpenScm()
{
	g_ScmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
	return g_ScmHandle != nullptr;
}


void loader::CloseScm()
{
	CloseServiceHandle(g_ScmHandle);
}

SC_HANDLE loader::CreateService(const std::string& ServiceName, const std::string& DisplayName, const std::string& DriverPath)
{
	auto ServiceHandle = CreateServiceA(
		g_ScmHandle,
		ServiceName.c_str(),
		DisplayName.c_str(),
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		DriverPath.c_str(),
		nullptr, nullptr, nullptr, nullptr, nullptr
	);

	// If service already exists, open it
	if (!ServiceHandle && GetLastError() == ERROR_SERVICE_EXISTS)
		ServiceHandle = OpenServiceA(g_ScmHandle, ServiceName.c_str(), SERVICE_ALL_ACCESS);

	return ServiceHandle;
}

bool loader::DeleteService(const SC_HANDLE ServiceHandle)
{
	const auto Success = static_cast<bool>(::DeleteService(ServiceHandle));

	if (!Success && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
		return false;

	return static_cast<bool>(CloseServiceHandle(ServiceHandle));
}

bool loader::StartService(const SC_HANDLE ServiceHandle)
{
	const auto Success = static_cast<bool>(::StartService(ServiceHandle, 0, nullptr));
	return Success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool loader::StopService(SC_HANDLE ServiceHandle, LPSERVICE_STATUS ServiceStatus)
{
	return static_cast<bool>(ControlService(ServiceHandle, SERVICE_CONTROL_STOP, ServiceStatus));
}