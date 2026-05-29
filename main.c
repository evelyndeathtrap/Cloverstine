#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <curl/curl.h>

#define BUFFER_SIZE 65536
#define KEY_FILE_NAME "GEMINI_API_KEY"

typedef int (*BytecodeFunc)(int, int);

struct ResponseBuffer {
    char data[BUFFER_SIZE];
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct ResponseBuffer *mem = (struct ResponseBuffer *)userp;

    if (mem->size + realsize < BUFFER_SIZE - 1) {
        memcpy(&(mem->data[mem->size]), contents, realsize);
        mem->size += realsize;
        mem->data[mem->size] = 0;
    }
    return realsize;
}

void list_available_raw_files(void) {
    DIR *d = opendir(".");
    int count = 0;
    
    printf("\n[ Workspace ] Listing local bytecode blocks (*.raw):\n");
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            char *ext = strrchr(dir->d_name, '.');
            if (ext && strcmp(ext, ".raw") == 0) {
                printf("  -> %s\n", dir->d_name);
                count++;
            }
        }
        closedir(d);
    }
    if (count == 0) {
        printf("  (No *.raw files found)\n");
    }
    printf("\n");
}

int load_api_key(char *dest, size_t max_len) {
    FILE *f = fopen(KEY_FILE_NAME, "r");
    if (f) {
        if (fgets(dest, max_len, f)) {
            dest[strcspn(dest, "\r\n")] = '\0';
            fclose(f);
            if (strlen(dest) > 0) return 1;
        }
        fclose(f);
    }
    const char *env_key = getenv("GEMINI_API_KEY");
    if (env_key && strlen(env_key) > 0) {
        strncpy(dest, env_key, max_len - 1);
        dest[max_len - 1] = '\0';
        return 1;
    }
    return 0;
}

// Extract raw content inside Gemini JSON "text" response string block
void extract_clean_source(const char *json, char *output, size_t max_len) {
    const char *target = "\"text\": \"";
    char *start = strstr(json, target);
    if (!start) {
        strncpy(output, "", max_len);
        return;
    }
    start += strlen(target);
    
    size_t out_idx = 0;
    int in_markdown = 0;

    while (*start && *start != '"' && out_idx < max_len - 1) {
        // Look past basic escaped structural characters or Markdown definitions back-to-back
        if (strncmp(start, "```c", 4) == 0) { start += 4; in_markdown = 1; continue; }
        if (strncmp(start, "```", 3) == 0) { start += 3; in_markdown = 0; continue; }
        if (*start == '\\' && *(start + 1) == 'n') {
            output[out_idx++] = '\n';
            start += 2;
            continue;
        }
        if (*start == '\\' && *(start + 1) == '"') {
            output[out_idx++] = '"';
            start += 2;
            continue;
        }
        if (*start == '\\' && *(start + 1) == 't') {
            output[out_idx++] = '\t';
            start += 2;
            continue;
        }
        
        output[out_idx++] = *start++;
    }
    output[out_idx] = '\0';
}

void execute_raw_file(const char *filename, int p1, int p2) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "[ Storage ] Target file missing or invalid: %s\n", filename);
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fprintf(stderr, "[ Failure ] Target runtime binary file payload is empty.\n");
        fclose(f);
        return;
    }

    unsigned char *buffer = malloc(size);
    if (!buffer) { fclose(f); return; }
    size_t read_bytes = fread(buffer, 1, size, f);
    fclose(f);

    void *exec_mem = mmap(NULL, read_bytes, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("[ Engine ] Execution context memory allocation page fault");
        free(buffer);
        return;
    }

    memcpy(exec_mem, buffer, read_bytes);
    free(buffer);

    BytecodeFunc LoadedFunc = (BytecodeFunc)exec_mem;
    printf("[ Engine ] Executing file-loaded bytecode '%s' with inputs (%d, %d)...\n", filename, p1, p2);
    int res_val = LoadedFunc(p1, p2);
    printf("[ Engine ] Return code evaluated: %d\n", res_val);

    munmap(exec_mem, read_bytes);
}

void compile_source_to_raw(const char *c_code, const char *save_filename) {
    FILE *src = fopen("temp_jit.c", "w");
    if (!src) {
        fprintf(stderr, "[ Failure ] Failed to create temporary source file.\n");
        return;
    }
    // Automatically wrap includes just in case the LLM outputs only raw functions
    fprintf(src, "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <math.h>\n");
    fprintf(src, "%s\n", c_code);
    fclose(src);

    char cmd[1024];
    // Compile to shared library object 
    snprintf(cmd, sizeof(cmd), "cc -O2 -shared -fPIC temp_jit.c -o temp_jit.so -lm");
    if (system(cmd) != 0) {
        fprintf(stderr, "[ Failure ] Local cc engine compilation failed. Invalid C syntax.\n");
        unlink("temp_jit.c");
        return;
    }

    // Extract text segment out directly into raw application bytecode machine code file
    snprintf(cmd, sizeof(cmd), "objcopy -O binary --only-section=.text temp_jit.so %s", save_filename);
    if (system(cmd) != 0) {
        fprintf(stderr, "[ Failure ] Extracting machine bytecode via objcopy failed.\n");
    } else {
        printf("[ Storage ] Successfully generated compiled bytecode asset -> %s\n", save_filename);
    }

    unlink("temp_jit.c");
    unlink("temp_jit.so");
}

void prompt_gemini_and_build(const char *api_key, const char *prompt, const char *save_filename) {
    CURL *curl;
    CURLcode res;
    struct ResponseBuffer response = { .size = 0 };
    char url[512];

    snprintf(url, sizeof(url), "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=%s", api_key);

    // Escape basic quotation constraints safely 
    char escaped_prompt[2048] = {0};
    size_t ep_idx = 0;
    for (size_t i = 0; prompt[i] != '\0' && ep_idx < sizeof(escaped_prompt) - 2; i++) {
        if (prompt[i] == '"' || prompt[i] == '\\') {
            escaped_prompt[ep_idx++] = '\\';
        }
        escaped_prompt[ep_idx++] = prompt[i];
    }

    char json_payload[4096];
    snprintf(json_payload, sizeof(json_payload),
             "{\"contents\": [{\"parts\": [{\"text\": \"Write a single pure C language function named custom_func taking two integers and returning an integer: 'int custom_func(int a, int b)'. Output only code block structure markdown context. No extra chatter or descriptions. Goal: %s\"}]}]}",
             escaped_prompt);

    curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    printf("[ Pipeline ] Fetching custom C implementation from Gemini API...\n");
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "[ Failure ] Network transmission failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return;
    }

    char clean_c_code[8192];
    extract_clean_source(response.data, clean_c_code, sizeof(clean_c_code));

    if (strlen(clean_c_code) == 0) {
        fprintf(stderr, "[ Failure ] Empty content extraction returned from API layer.\n");
    } else {
        printf("[ Local CC ] Source extracted:\n%s\n", clean_c_code);
        compile_source_to_raw(clean_c_code, save_filename);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

int main(int argc, char *argv[]) {
    char api_key[256] = {0};
    int has_key = load_api_key(api_key, sizeof(api_key));
    int test_a = 14, test_b = 3;

    curl_global_init(CURL_GLOBAL_ALL);

    // CRITICAL: Immediate check for direct binary file via argv command line arguments
    if (argc > 1 && strcmp(argv[1], "run") != 0) {
        // If file exists, immediately execute it and close out
        if (access(argv[1], F_OK) == 0) {
            printf("[ Exec ] CLI parameter match found: Loading %s\n", argv[1]);
            execute_raw_file(argv[1], test_a, test_b);
            goto cleanup;
        }
    }

    char user_prompt[1024];
    char target_bin[256] = "output_bytecode.raw";

    printf("=== LLM dynamic C Function Engine ===\n");
    list_available_raw_files();

    printf("Enter command (e.g., 'run filename.raw') OR type an instructions prompt for Gemini:\n> ");
    if (!fgets(user_prompt, sizeof(user_prompt), stdin)) {
        goto cleanup;
    }
    user_prompt[strcspn(user_prompt, "\r\n")] = '\0';

    // Check if the command starts with "run"
    if (strncmp(user_prompt, "run", 3) == 0) {
        char *filename = user_prompt + 3;
        while (*filename == ' ') filename++; // drop padded tracking spaces

        if (strlen(filename) == 0) {
            fprintf(stderr, "[ Error ] Specify target file destination path: 'run <file>'\n");
        } else {
            printf("\nEnter validation arguments separated by space (default '14 3'):\n> ");
            char input_buf[64];
            if (fgets(input_buf, sizeof(input_buf), stdin)) {
                sscanf(input_buf, "%d %d", &test_a, &test_b);
            }
            execute_raw_file(filename, test_a, test_b);
        }
    } else {
        // Standard flow: Query Gemini for C file, build it locally
        if (!has_key) {
            fprintf(stderr, "[ Critical Error ] Gemini API key authentication token context missing.\n");
            goto cleanup;
        }

        printf("\nEnter target output file name context destination (default: 'output_bytecode.raw'):\n> ");
        char file_input[256];
        if (fgets(file_input, sizeof(file_input), stdin)) {
            file_input[strcspn(file_input, "\r\n")] = '\0';
            if (strlen(file_input) > 0) {
                strncpy(target_bin, file_input, sizeof(target_bin) - 1);
            }
        }
        if (!strstr(target_bin, ".raw") && strlen(target_bin) < 250) {
            strcat(target_bin, ".raw");
        }

        prompt_gemini_and_build(api_key, user_prompt, target_bin);
        
        // Execute newly created function immediately
        execute_raw_file(target_bin, test_a, test_b);
    }

cleanup:
    curl_global_cleanup();
    return 0;
}
