
#include <windows.h>
#include <stdio.h>

#define BUF_LEN 1024

int main(void) {
    const wchar_t* directory = L"C:\\Personal\\Coding_Local\\05-zig\\07-Ziggatch\\.zig-cache\\tmp";

    HANDLE hDir = CreateFileW(
        directory,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        printf("Failed to open directory: %lu\n", GetLastError());
        return 1;
    }

    BYTE buffer[BUF_LEN];
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (overlapped.hEvent == NULL) {
        printf("Failed to create event: %lu\n", GetLastError());
        CloseHandle(hDir);
        return 1;
    }

    DWORD bytesReturned = 0;

    // Start the initial async read
    BOOL success = ReadDirectoryChangesW(
        hDir,
        buffer,
        sizeof(buffer),
        TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
        FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
        FILE_NOTIFY_CHANGE_LAST_WRITE,
        &bytesReturned,
        &overlapped,
        NULL
    );

    if (!success && GetLastError() != ERROR_IO_PENDING) {
        printf("Initial ReadDirectoryChangesW failed: %lu\n", GetLastError());
        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        return 1;
    }

    // ✅ Print directory name once at startup
    wprintf(L"Monitoring: %ls\n", directory);

    while (1) {
        // Try to get result non-blocking
        DWORD bytesTransferred = 0;
        BOOL complete = GetOverlappedResult(hDir, &overlapped, &bytesTransferred, FALSE);

        if (complete) {
            FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buffer;
            do {
                char filename[MAX_PATH];
                int len = WideCharToMultiByte(CP_UTF8, 0, fni->FileName,
                    fni->FileNameLength / sizeof(WCHAR),
                    filename, MAX_PATH, NULL, NULL);
                filename[len] = '\0';

                // ✅ Only prints when there's actually a change
                printf("Action: %lu, File: %s\n", fni->Action, filename);

                if (fni->NextEntryOffset == 0) break;
                fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
            } while (1);

            // Re-arm the watch
            ResetEvent(overlapped.hEvent);
            bytesReturned = 0;
            success = ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                &overlapped,
                NULL
            );

            if (!success && GetLastError() != ERROR_IO_PENDING) {
                printf("Re-issue failed: %lu\n", GetLastError());
                break;
            }
        }

        // Don't print anything if no change — silent polling
        Sleep(100);
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
    return 0;
}
