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
#define MAX_RETRIES 4

// Standard function pointer signature for our dynamic target evaluations
typedef int (*BytecodeFunc)(int, int);

struct ResponseBuffer {
    char data[BUFFER_SIZE];
    size_t size;
};

// Standard write callback for libcurl to dump incoming response chunk payloads
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

// Scans current directory working space for compiled raw machine binary blocks
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

// Loads our Gemini API key from local storage file or systems environment 
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

// Decodes and extracts code contents directly out of the incoming Gemini JSON context,
// unescaping unicode sequences like \u003c and standard JSON escapes.
void extract_clean_source(const char *json, char *output, size_t max_len) {
    const char *target = "\"text\": \"";
    char *start = strstr(json, target);
    if (!start) {
        strncpy(output, "", max_len);
        return;
    }
    start += strlen(target);
    
    size_t out_idx = 0;
    while (*start && *start != '"' && out_idx < max_len - 1) {
        // Strip markdown backticks standard output formats safely
        if (strncmp(start, "```c", 4) == 0) { start += 4; continue; }
        if (strncmp(start, "```", 3) == 0) { start += 3; continue; }
        
        // Handle JSON Escape decoding
        if (*start == '\\') {
            if (*(start + 1) == 'n') {
                output[out_idx++] = '\n';
                start += 2;
            } else if (*(start + 1) == '"') {
                output[out_idx++] = '"';
                start += 2;
            } else if (*(start + 1) == '\\') {
                output[out_idx++] = '\\';
                start += 2;
            } else if (*(start + 1) == 't') {
                output[out_idx++] = '\t';
                start += 2;
            } else if (*(start + 1) == 'r') {
                output[out_idx++] = '\r';
                start += 2;
            } else if (*(start + 1) == 'f') {
                output[out_idx++] = '\f';
                start += 2;
            } else if (*(start + 1) == 'b') {
                output[out_idx++] = '\b';
                start += 2;
            } else if (*(start + 1) == '/') {
                output[out_idx++] = '/';
                start += 2;
            } else if (*(start + 1) == 'u') {
                // Decode \uXXXX Unicode hexadecimal sequences
                if (start[2] && start[3] && start[4] && start[5]) {
                    char hex[5] = { start[2], start[3], start[4], start[5], '\0' };
                    unsigned int codepoint = (unsigned int)strtol(hex, NULL, 16);
                    
                    // Standard ASCII translation
                    if (codepoint < 128) {
                        output[out_idx++] = (char)codepoint;
                    } else if (codepoint < 0x800) { // Multi-byte UTF-8 translation for robustness
                        if (out_idx < max_len - 2) {
                            output[out_idx++] = (char)(0xC0 | (codepoint >> 6));
                            output[out_idx++] = (char)(0x80 | (codepoint & 0x3F));
                        }
                    } else {
                        if (out_idx < max_len - 3) {
                            output[out_idx++] = (char)(0xE0 | (codepoint >> 12));
                            output[out_idx++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
                            output[out_idx++] = (char)(0x80 | (codepoint & 0x3F));
                        }
                    }
                    start += 6;
                } else {
                    output[out_idx++] = *start++;
                }
            } else {
                // Non-standard escape fallback
                output[out_idx++] = *start++;
            }
            continue;
        }
        output[out_idx++] = *start++;
    }
    output[out_idx] = '\0';
}

// Maps, copies, and dynamically executes raw machine instructions directly inside a virtual page
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
        fprintf(stderr, "[ Failure ] Target binary file payload is empty.\n");
        fclose(f);
        return;
    }

    unsigned char *buffer = malloc(size);
    if (!buffer) { fclose(f); return; }
    size_t read_bytes = fread(buffer, 1, size, f);
    fclose(f);

    // Secure an executable, writeable and readable private page boundary
    void *exec_mem = mmap(NULL, read_bytes, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("[ Engine ] Memory allocation page fault on JIT generation");
        free(buffer);
        return;
    }

    memcpy(exec_mem, buffer, read_bytes);
    free(buffer);

    BytecodeFunc LoadedFunc = (BytecodeFunc)exec_mem;
    printf("[ Engine ] Executing bytecode '%s' with inputs (%d, %d)...\n", filename, p1, p2);
    int res_val = LoadedFunc(p1, p2);
    printf("[ Engine ] Return code evaluated: %d\n", res_val);

    munmap(exec_mem, read_bytes);
}

// Escapes critical structures for secure, stringified transit within JSON packages
void json_escape(const char *src, char *dest, size_t max_len) {
    size_t d_idx = 0;
    for (size_t i = 0; src[i] != '\0' && d_idx < max_len - 3; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            dest[d_idx++] = '\\';
            dest[d_idx++] = src[i];
        } else if (src[i] == '\n') {
            dest[d_idx++] = '\\';
            dest[d_idx++] = 'n';
        } else {
            dest[d_idx++] = src[i];
        }
    }
    dest[d_idx] = '\0';
}

// Helper to pull text from disk directly back into dynamic string context buffers
char *read_file_to_string(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *str = malloc(size + 1);
    if (str) {
        size_t read_bytes = fread(str, 1, size, f);
        str[read_bytes] = '\0';
    }
    fclose(f);
    return str;
}

// Interfaces with the Gemini API to request code transformations
int invoke_gemini_api(const char *api_key, const char *prompt, char *output_source, size_t max_len) {
    CURL *curl;
    CURLcode res;
    struct ResponseBuffer response = { .size = 0 };
    char url[1024];
    static char json_payload[BUFFER_SIZE];

    // Automatically check for custom URL configuration in environment variables
    const char *env_url = getenv("GEMINI_API_URL");
    if (env_url && strlen(env_url) > 0) {
        // If API key is already embedded in the custom URL, use it directly
        if (strstr(env_url, "key=")) {
            snprintf(url, sizeof(url), "%s", env_url);
        } else {
            // Append API key cleanly, detecting query parameters
            char separator = strchr(env_url, '?') ? '&' : '?';
            snprintf(url, sizeof(url), "%s%ckey=%s", env_url, separator, api_key);
        }
    } else {
        // Default preview environment API endpoint
        snprintf(url, sizeof(url), "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=%s", api_key);
    }

    static char escaped_prompt[BUFFER_SIZE / 2];
    json_escape(prompt, escaped_prompt, sizeof(escaped_prompt));

    snprintf(json_payload, sizeof(json_payload),
             "{\"contents\": [{\"parts\": [{\"text\": \"%s\"}]}]}",
             escaped_prompt);

    curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    res = curl_easy_perform(curl);
    
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[ API Connection ] libcurl connection failed: %s\n", curl_easy_strerror(res));
        return 0;
    }

    extract_clean_source(response.data, output_source, max_len);
    
    // Diagnostic enhancement: Show the real response details if extraction fails
    if (strlen(output_source) == 0) {
        fprintf(stderr, "[ API Diagnostic ] Error: Unable to extract structured C code from response.\n");
        fprintf(stderr, "[ API Diagnostic ] HTTP Status Code: %ld\n", http_code);
        fprintf(stderr, "[ API Diagnostic ] Raw JSON Payload:\n%s\n", response.data);
        return 0;
    }

    return 1;
}

// Executes the main feedback negotiation and local C compilation loop
void auto_negotiate_and_build(const char *api_key, const char *initial_prompt, const char *save_filename) {
    static char current_prompt[BUFFER_SIZE / 2];
    static char extracted_c_code[8192];
    
    // Highly engineered system prompt predicting and eliminating compilation & JIT issues
    snprintf(current_prompt, sizeof(current_prompt),
             "You are a low-level embedded software engine helper. Write a single self-contained C function named 'custom_func' taking two integers and returning an integer: 'int custom_func(int a, int b)'.\n\n"
             "CRITICAL ARCHITECTURAL CONSTRAINTS:\n"
             "1. STRICT SIGNATURE: Your function signature must be exactly: int custom_func(int a, int b)\n"
             "2. NO STRING LITERALS OR CONSTANT STRINGS: Do not use any strings like \"text\", printf(), puts(), or sprintf(). These are compiled into .rodata, which is stripped by the engine and will trigger immediate segmentation faults.\n"
             "3. NO GLOBAL OR STATIC VARIABLES: All calculations must use standard local stack-allocated variables.\n"
             "4. standard math.h functions (like sin, cos, pow, sqrt) are available if needed.\n"
             "5. STRICT FORMATTING: Output ONLY raw C code enclosed in a markdown code block (using triple backticks and 'c'). Absolutely no conversational text, preambles, or explanations.\n\n"
             "Goal requirement: %s",
             initial_prompt);

    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        printf("[ Pipeline ] (Attempt %d/%d) Querying Gemini API...\n", attempt, MAX_RETRIES);
        
        if (!invoke_gemini_api(api_key, current_prompt, extracted_c_code, sizeof(extracted_c_code))) {
            fprintf(stderr, "[ Failure ] Compiler pipeline aborted due to API error.\n");
            return;
        }

        // Output code payload to disk for the compiler
        FILE *src = fopen("temp_jit.c", "w");
        if (!src) return;
        fprintf(src, "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <math.h>\n");
        fprintf(src, "%s\n", extracted_c_code);
        fclose(src);

        // Compile dynamically, capture error diagnostics
        // We use optimal JIT extraction flags: -fno-asynchronous-unwind-tables to strip EH frames, ensuring only clean bytecode is emitted
        printf("[ Local CC ] Calling local compiler 'cc'...\n");
        int cc_status = system("cc -O3 -shared -fPIC -fno-asynchronous-unwind-tables -fomit-frame-pointer temp_jit.c -o temp_jit.so -lm 2> cc_errors.log");

        if (cc_status == 0) {
            // Success! Extract raw assembly/machine code .text bytes from the compiled dynamic object
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "objcopy -O binary --only-section=.text temp_jit.so %s", save_filename);
            if (system(cmd) == 0) {
                printf("[ Success ] Successfully compiled and linked on attempt %d! Saved block -> %s\n", attempt, save_filename);
                unlink("temp_jit.c");
                unlink("temp_jit.so");
                unlink("cc_errors.log");
                return;
            }
        }

        // Failure! Extract compiler feedback diagnostics and loop them back into the next prompt
        char *errors = read_file_to_string("cc_errors.log");
        if (errors && strlen(errors) > 0) {
            printf("[ Local CC ] Compilation failed! Starting negotiation phase...\n");
            printf("--- Diagnostic Output ---\n%s-----------------------\n", errors);
            
            // Auto-reorganization prompt: guides Gemini directly on the specific errors found
            snprintf(current_prompt, sizeof(current_prompt),
                     "Your previous C code implementation has failed to compile.\n\n"
                     "INSTRUCTIONS TO CORRECT THE IMPLEMENTATION:\n"
                     "1. Fix the compiler syntax or semantic errors listed below.\n"
                     "2. Remember to retain the signature 'int custom_func(int a, int b)'.\n"
                     "3. NEVER introduce any string literals, global variables, or static structures.\n"
                     "4. Output ONLY the corrected C code block inside triple backticks. Do not include explanations.\n\n"
                     "FAILED CODE:\n"
                     "```c\n%s\n```\n\n"
                     "COMPILER ERRORS:\n"
                     "```\n%s\n```",
                     extracted_c_code, errors);
        } else {
            snprintf(current_prompt, sizeof(current_prompt),
                     "The compilation run was aborted. Please write the custom_func implementation from scratch again following basic standard C conventions.");
        }
        free(errors);
    }

    fprintf(stderr, "[ Failure ] Failed to reach compiler convergence after %d loops. Program aborted.\n", MAX_RETRIES);
    unlink("temp_jit.c");
    unlink("temp_jit.so");
    unlink("cc_errors.log");
}

int main(int argc, char *argv[]) {
    char api_key[256] = {0};
    int has_key = load_api_key(api_key, sizeof(api_key));
    int test_a = 14, test_b = 3;

    curl_global_init(CURL_GLOBAL_ALL);

    // Dynamic execution optimization: Check if first arg matches local file on disk
    if (argc > 1) {
        char *check_file = argv[1];
        if (strcmp(argv[1], "run") == 0 && argc > 2) {
            check_file = argv[2];
        }
        if (access(check_file, F_OK) == 0) {
            printf("[ Exec ] Fastpath match on CLI parameter: executing '%s'\n", check_file);
            execute_raw_file(check_file, test_a, test_b);
            goto cleanup;
        }
    }

    char user_prompt[1024];
    char target_bin[256] = "output_bytecode.raw";

    printf("=== LLM Dynamic Auto-Correction C Engine ===\n");
    list_available_raw_files();

    printf("Enter command (e.g. 'run filename.raw') OR type structural instructions for Gemini:\n> ");
    if (!fgets(user_prompt, sizeof(user_prompt), stdin)) {
        goto cleanup;
    }
    user_prompt[strcspn(user_prompt, "\r\n")] = '\0';

    if (strncmp(user_prompt, "run", 3) == 0) {
        char *filename = user_prompt + 3;
        while (*filename == ' ') filename++;

        if (strlen(filename) == 0) {
            fprintf(stderr, "[ Error ] Specify target destination: 'run <file.raw>'\n");
        } else {
            printf("\nEnter two test execution inputs (space-separated, default '14 3'):\n> ");
            char input_buf[64];
            if (fgets(input_buf, sizeof(input_buf), stdin)) {
                sscanf(input_buf, "%d %d", &test_a, &test_b);
            }
            execute_raw_file(filename, test_a, test_b);
        }
    } else {
        if (!has_key) {
            fprintf(stderr, "[ Critical Error ] Authentication key context could not be resolved.\n");
            goto cleanup;
        }

        printf("\nEnter filename to output raw machine code (default: 'output_bytecode.raw'):\n> ");
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

        auto_negotiate_and_build(api_key, user_prompt, target_bin);
        execute_raw_file(target_bin, test_a, test_b);
    }

cleanup:
    curl_global_cleanup();
    return 0;
}
