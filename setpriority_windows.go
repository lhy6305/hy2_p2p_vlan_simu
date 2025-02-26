// code from https://stackoverflow.com/questions/36928541

package main

import (
	"golang.org/x/sys/windows"
)

// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
const windows_PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff

func windows_SetPriority(pid int, priority uint32) error {
	handle, err := windows.OpenProcess(windows_PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle) // Technically this can fail, but we ignore it

	err = windows.SetPriorityClass(handle, priority)
	if err != nil {
		return err
	}

	return nil
}
