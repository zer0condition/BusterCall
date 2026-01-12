#pragma once

#include <Windows.h>
#include <string>

namespace loader
{
	bool OpenScm();
	void CloseScm();
	SC_HANDLE CreateService(const std::string& ServiceName, const std::string& DisplayName, const std::string& DriverPath);
	bool DeleteService(const SC_HANDLE ServiceHandle);
	bool StartService(const SC_HANDLE ServiceHandle);
	bool StopService(const SC_HANDLE ServiceHandle, LPSERVICE_STATUS ServiceStatus);
}