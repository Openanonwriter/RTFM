// Writen by Anthony Widick 
// 3/25/2024, 2:41AM and I have work at 8:30
// V0.1
// Released under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
// This is my first C program, and my first acutal .EXE 

#include <unistd.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h> 

char *get_exe_directory() {
    char *buffer = malloc(128);  // Allocate an initial buffer
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    DWORD size = 128; 
    size = GetModuleFileNameA(NULL, buffer, size);
    if (size == 0) {
        DWORD error_code = GetLastError();
        fprintf(stderr, "GetModuleFileNameA failed, error code: %d\n", error_code);
        return NULL; 
    }

    while (size == GetModuleFileNameA(NULL, buffer, size)) {
        buffer = realloc(buffer, size * 2);
        size *= 2; 
    }

    // Extract the directory portion
    char *last_backslash = strrchr(buffer, '\\'); 
    if (last_backslash != NULL) {
        *last_backslash = '\0'; 
    }

    return buffer;
    system("pause"); // Windows-specific command
}

int main() {
    // Get the executable's directory
    char *exe_directory = get_exe_directory();
    if (exe_directory == NULL) {
        return 1; // Indicate an error
    }

    // Construct the path to the RTFM.ps1 script
    const char *script_name = "RTFM.ps1";
    int ps_script_path_len = strlen(exe_directory) + strlen(script_name) + 2; // +1 for slash, +1 for null terminator
    char *ps_script_path = malloc(ps_script_path_len); 
    if (ps_script_path == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        free(exe_directory);
        return 1; 
    }
    snprintf(ps_script_path, ps_script_path_len, "%s\\%s", exe_directory, script_name); 

    // Check if the script exists
    if (access(ps_script_path, 0) != 0) { 
        fprintf(stderr, "Error: RTFM.ps1 not found in the same directory.\n");
        free(exe_directory); 
        free(ps_script_path); 
        return 1; 
    }

    // Execute PowerShell
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si); 
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); 
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    char command_line[MAX_PATH];
    snprintf(command_line, MAX_PATH, "powershell.exe -File \"%s\"", ps_script_path);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "Error: Failed to create process.\n");
        free(exe_directory); 
        free(ps_script_path); 
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE); 

    // Close process handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Cleanup
    free(exe_directory); 
    free(ps_script_path); 
    

    return 0; 
}
