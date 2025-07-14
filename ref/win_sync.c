
#include <windows.h>
#include <stdio.h>

int main() {
    // Directory to watch - change as needed
    LPCWSTR directory = L"C:\\Personal\\Coding_Local\\05-zig\\07-Ziggatch\\.zig-cache\\tmp";

    // Buffer to receive notifications
    char buffer[1024];
    DWORD bytesReturned;

    // Get handle to the directory
    HANDLE hDir = CreateFileW(
        directory,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,  // needed to open a directory handle
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        printf("Failed to get directory handle. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("Watching directory: %ws\n", directory);

    while (1) {
        BOOL success = ReadDirectoryChangesW(
            hDir,
            &buffer,
            sizeof(buffer),
            TRUE, // watch subdirectories
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            NULL,
            NULL
        );

        if (!success) {
            printf("ReadDirectoryChangesW failed. Error: %lu\n", GetLastError());
            break;
        }

        if (bytesReturned > 0) {
            printf("Change detected in directory!\n");
            // For simplicity, we just print that something changed.
            // Parsing FILE_NOTIFY_INFORMATION is possible but more code.
        }
    }

    CloseHandle(hDir);
    return 0;
}
