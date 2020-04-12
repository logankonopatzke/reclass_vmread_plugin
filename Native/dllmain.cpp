#include <cstdint>

#include <ReClassNET_Plugin.hpp>

#include "../vmread/hlapi/hlapi.h"

typedef struct WinPage
{
	uint64_t address;
	size_t size;
} WinPage;

typedef struct WinPageList
{
	WinPage *list;
	size_t size;
} WinPageList;

// This should definitely be moved elsewhere
WinPageList GeneratePageList(const WinCtx *ctx, const WinProc *process)
{
	WinPageList list;
	uint64_t pVadRoot = process->physProcess + 0x658; // win10 build 18362
	uint64_t VadCount = MemReadU64(&ctx->process, pVadRoot + 0x10);
	list.size = 0;
	list.list = (WinPage *)malloc(sizeof(WinPage) * VadCount);
	uint64_t *toVisit = (uint64_t *)malloc(sizeof(uint64_t) * VadCount);
	toVisit[0] = pVadRoot;
	size_t enqued = 1;

	// Walk AVL tree from the VadRoot via depth first search
	while (enqued != 0)
	{
		uint64_t curNode = toVisit[--enqued];
		uint64_t virtVadNode = MemReadU64(&ctx->process, curNode);
		if (virtVadNode == 0)
		{
			continue;
		}
		uint64_t physVadNode = VTranslate(&ctx->process, process->dirBase, virtVadNode);
		toVisit[enqued++] = physVadNode;	   // Left
		toVisit[enqued++] = physVadNode + 0x8; // Right
		uint64_t pStartingVpn = physVadNode + 24,
				 pEndingVpn = physVadNode + 28,
				 pStartingVpnHigh = physVadNode + 32,
				 pEndingVpnHigh = physVadNode + 33;
		uint64_t StartingVpn = 0,
				 EndingVpn = 0,
				 StartingVpnHigh = 0,
				 EndingVpnHigh = 0;
		MemRead(&ctx->process, (uint64_t)&StartingVpn, pStartingVpn, sizeof(uint32_t));
		MemRead(&ctx->process, (uint64_t)&EndingVpn, pEndingVpn, sizeof(uint32_t));
		MemRead(&ctx->process, (uint64_t)&StartingVpnHigh, pStartingVpnHigh, sizeof(uint8_t));
		MemRead(&ctx->process, (uint64_t)&EndingVpnHigh, pEndingVpnHigh, sizeof(uint8_t));

		uint64_t start = (StartingVpn << 12) | (StartingVpnHigh << 44);
		uint64_t end = (((EndingVpn + 1) << 12) | (EndingVpnHigh << 44));
		list.list[list.size].address = start;
		list.list[list.size++].size = end - start;
		if (list.size >= VadCount)
			break;
	}

	free(toVisit);
	return list;
}

// We should really have this in a try catch block in case it does throw
// TODO: Handle resulting errors and present them in reclass
static WinContext vmread_context(0);

/// <summary>Enumerate all processes on the system.</summary>
/// <param name="callbackProcess">The callback for a process.</param>
extern "C" void RC_CallConv EnumerateProcesses(EnumerateProcessCallback callbackProcess)
{
	if (callbackProcess == nullptr)
	{
		return;
	}

	vmread_context.processList.Refresh(); // Refresh the process list

	for (const auto &it : vmread_context.processList) // Iterate through active processes
	{
		EnumerateProcessData data{};
		data.Id = it.proc.pid;											  // Set pid
		MultiByteToUnicode(it.proc.name, data.Name, PATH_MAXIMUM_LENGTH); // Set name
		MultiByteToUnicode("Unknown", data.Path, PATH_MAXIMUM_LENGTH);	  // We aren't able to get the full path from vmread so just set it to unknown

		callbackProcess(&data);
	}
}

/// <summary>Enumerate all sections and modules of the remote process.</summary>
/// <param name="process">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="callbackSection">The callback for a section.</param>
/// <param name="callbackModule">The callback for a module.</param>
extern "C" void RC_CallConv EnumerateRemoteSectionsAndModules(RC_Pointer handle, EnumerateRemoteSectionsCallback callbackSection, EnumerateRemoteModulesCallback callbackModule)
{
	if (callbackSection == nullptr || callbackModule == nullptr)
	{
		return;
	}

	const auto process = reinterpret_cast<WinProcess *>(handle);

	const auto pages = GeneratePageList(process->ctx, &process->proc);
	for (size_t i = 0; i < pages.size; ++i)
	{
		EnumerateRemoteSectionData data{};
		data.BaseAddress = reinterpret_cast<RC_Pointer>(pages.list[i].address);
		data.Size = pages.list[i].size;
		data.Type = SectionType::Image;
		data.Category = SectionCategory::Unknown;
		data.Protection = SectionProtection::Read;

		// Get the name of the module containing the section
		for (const auto &it : process->modules)
		{
			const uint64_t start = it.info.baseAddress;
			const uint64_t end = start + it.info.sizeOfModule;

			if (pages.list[i].address >= start && pages.list[i].address <= end)
			{
				MultiByteToUnicode(it.info.name, data.ModulePath, PATH_MAXIMUM_LENGTH); // Set path to correct module
			}
		}

		callbackSection(&data);
	}

	for (const auto &it : process->modules)
	{
		EnumerateRemoteModuleData data{};
		data.BaseAddress = reinterpret_cast<RC_Pointer>(it.info.baseAddress);
		data.Size = it.info.sizeOfModule;
		MultiByteToUnicode(it.info.name, data.Path, PATH_MAXIMUM_LENGTH);

		callbackModule(&data);
	}
}

/// <summary>Opens the remote process.</summary>
/// <param name="id">The identifier of the process returned by EnumerateProcesses.</param>
/// <param name="desiredAccess">The desired access.</param>
/// <returns>A handle to the remote process or nullptr if an error occured.</returns>
extern "C" RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess desiredAccess)
{
	vmread_context.processList.Refresh(); // Refresh the process list

	for (auto &it : vmread_context.processList) // Iterate through active processes
	{
		if (it.proc.pid == reinterpret_cast<uint64_t>(id))
			return reinterpret_cast<RC_Pointer>(&it);
	}

	return nullptr;
}

/// <summary>Queries if the process is valid.</summary>
/// <param name="handle">The process handle obtained by OpenRemoteProcess.</param>
/// <returns>True if the process is valid, false if not.</returns>
extern "C" bool RC_CallConv IsProcessValid(RC_Pointer handle)
{
	return handle; // As long as the handle is non zero it should be valid in this case
}

/// <summary>Closes the handle to the remote process.</summary>
/// <param name="handle">The process handle obtained by OpenRemoteProcess.</param>
extern "C" void RC_CallConv CloseRemoteProcess(RC_Pointer handle)
{
	// VMRead doesn't require us to close any handle
}

/// <summary>Reads memory of the remote process.</summary>
/// <param name="handle">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="address">The address to read from.</param>
/// <param name="buffer">The buffer to read into.</param>
/// <param name="offset">The offset into the buffer.</param>
/// <param name="size">The number of bytes to read.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv ReadRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	const auto process = reinterpret_cast<WinProcess *>(handle);
	return (VMemRead(&process->ctx->process, process->proc.dirBase, reinterpret_cast<uint64_t>(buffer) + offset, reinterpret_cast<uint64_t>(address), size) != -1);
}

/// <summary>Writes memory to the remote process.</summary>
/// <param name="process">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="address">The address to write to.</param>
/// <param name="buffer">The buffer to write.</param>
/// <param name="offset">The offset into the buffer.</param>
/// <param name="size">The number of bytes to write.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	const auto process = reinterpret_cast<WinProcess *>(handle);
	return (VMemWrite(&process->ctx->process, process->proc.dirBase, reinterpret_cast<uint64_t>(buffer) + offset, reinterpret_cast<uint64_t>(address), size) != -1);
}

/// <summary>Control the remote process (Pause, Resume, Terminate).</summary>
/// <param name="handle">The process handle obtained by OpenRemoteProcess.</param>
/// <param name="action">The action to perform.</param>
extern "C" void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action)
{
	// Perform the desired action on the remote process.

	// Not supported
}

/// <summary>Attach a debugger to the process.</summary>
/// <param name="id">The identifier of the process returned by EnumerateProcesses.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv AttachDebuggerToProcess(RC_Pointer id)
{
	// Attach a debugger to the remote process.

	// Not supported

	return false;
}

/// <summary>Detach a debugger from the remote process.</summary>
/// <param name="id">The identifier of the process returned by EnumerateProcesses.</param>
extern "C" void RC_CallConv DetachDebuggerFromProcess(RC_Pointer id)
{
	// Detach the debugger.

	// Not supported
}

/// <summary>Wait for a debug event within the given timeout.</summary>
/// <param name="evt">[out] The occured debug event.</param>
/// <param name="timeoutInMilliseconds">The timeout in milliseconds.</param>
/// <returns>True if an event occured within the given timeout, false if not.</returns>
extern "C" bool RC_CallConv AwaitDebugEvent(DebugEvent *evt, int timeoutInMilliseconds)
{
	// Wait for a debug event.

	// Not supported

	return false;
}

/// <summary>Handles the debug event described by evt.</summary>
/// <param name="evt">[in] The (modified) event returned by AwaitDebugEvent.</param>
extern "C" void RC_CallConv HandleDebugEvent(DebugEvent *evt)
{
	// Handle the debug event.

	// Not supported
}

/// <summary>Sets a hardware breakpoint.</summary>
/// <param name="processId">The identifier of the process returned by EnumerateProcesses.</param>
/// <param name="address">The address of the breakpoint.</param>
/// <param name="reg">The register to use.</param>
/// <param name="type">The type of the breakpoint.</param>
/// <param name="size">The size of the breakpoint.</param>
/// <param name="set">True to set the breakpoint, false to remove it.</param>
/// <returns>True if it succeeds, false if it fails.</returns>
extern "C" bool RC_CallConv SetHardwareBreakpoint(RC_Pointer id, RC_Pointer address, HardwareBreakpointRegister reg, HardwareBreakpointTrigger type, HardwareBreakpointSize size, bool set)
{
	// Set a hardware breakpoint with the given parameters.

	// Not supported

	return false;
}
