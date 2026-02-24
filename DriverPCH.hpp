#pragma once
#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "cppRuntime.hpp"
#include "Utilities.hpp"

using BOOL = int;
constexpr DWORD MAX_PATH = 260;
// SystemInformer has been gracious enough to have cutting edge RE'd windows definitions.
#pragma warning(push, 0) // SystemInformer's headers have a lot of warnings, so just disable them for the duration of including them
#include <phnt.h>
#pragma warning(pop)