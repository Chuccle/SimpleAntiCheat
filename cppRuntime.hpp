#pragma once

constexpr ULONG CppRuntimeTag = 'tRpC';

extern "C" NTSTATUS DriverCppInitialize();
extern "C" void DriverCppCleanup();