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

// Function pointer signature matching the expected machine code pattern (int fn(int, int))
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

// Scans current directory for compiled binary blobs
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

// Loads the API key from a local file, falls back to environment variable
int load_api_key(char *dest, size_t max_len) {
    FILE *f = fopen(KEY_FILE_NAME, "r");
    if (f) {
        if (fgets(dest, max_len, f)) {
            dest[strcspn(dest, "\r\n")] = '\0';
            fclose(f);
            if (strlen(dest) > 0) {
                printf("[ Auth ] Successfully initialized API key from file: %s\n", KEY_FILE_NAME);
                return 1;
            }
        }
        fclose(f);
    }

    const char *env_key = getenv("GEMINI_API_KEY");
    if (env_key && strlen(env_key) > 0) {
        strncpy(dest, env_key, max_len - 1);
        dest[max_len - 1] = '\0';
        printf("[ Auth ] Successfully initialized API key from environment variable.\n");
        return 1;
    }

    return 0;
}

// Decodes raw JSON response while skipping backticks and markdown code block pollution
void extract_clean_hex(const char *json, char *output, size_t max_len) {
    const char *target = "\"text\": \"";
    char *start = strstr(json, target);
    if (!start) {
        strncpy(output, "", max_len);
        return;
    }
    start += strlen(target);
    
    size_t out_idx = 0;
    while (*start && *start != '"' && out_idx < max_len - 1) {
        if (*start == '`' || *start == '\\' || *start == 'n' || *start == ' ' || *start == '\n') {
            start++;
            continue;
        }
        output[out_idx++] = *start++;
    }
    output[out_idx] = '\0';
}

unsigned char hex_to_byte(char hi, char lo) {
    unsigned char b = 0;
    if (hi >= '0' && hi <= '9') b += (hi - '0') << 4;
    else if (hi >= 'a' && hi <= 'f') b += (hi - 'a' + 10) << 4;
    else if (hi >= 'A' && hi <= 'F') b += (hi - 'A' + 10) << 4;

    if (lo >= '0' && lo <= '9') b += (lo - '0');
    else if (lo >= 'a' && lo <= 'f') b += (lo - 'a' + 10);
    else if (lo >= 'A' && lo <= 'F') b += (lo - 'A' + 10);
    return b;
}

size_t hex_string_to_bytes(const char *hex, unsigned char *dest, size_t max_size) {
    size_t len = strlen(hex);
    size_t byte_count = 0;
    for (size_t i = 0; i + 1 < len && byte_count < max_size; i += 2) {
        dest[byte_count++] = hex_to_byte(hex[i], hex[i+1]);
    }
    return byte_count;
}

void generate_and_call_prompt(const char *api_key, const char *prompt, const char *save_filename) {
    CURL *curl;
    CURLcode res;
    struct ResponseBuffer response = { .size = 0 };
    char url[512];

    snprintf(url, sizeof(url), "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=%s", api_key);

    char json_payload[2048];
    snprintf(json_payload, sizeof(json_payload),
             "{\"contents\": [{\"parts\": [{\"text\": \"Convert this instruction into pure raw x86_64 machine code bytes (System V AMD64 ABI calling convention). Output ONLY the consecutive hexadecimal string. No markdown, no spaces, no backticks, no text. Challenge: %s\"}]}]}",
             prompt);

    curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    printf("[ Pipeline ] Requesting compilation payload from Gemini...\n");
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "[ Failure ] Network transmission failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return;
    }

    char hex_output[4096];
    extract_clean_hex(response.data, hex_output, sizeof(hex_output));
    
    if (strlen(hex_output) == 0) {
        fprintf(stderr, "[ Failure ] Empty token payloads returned. (The model might have included unexpected formatting)\n");
        curl_easy_cleanup(curl);
        return;
    }

    printf("[ Pipeline ] Raw hex stream parsed: %s\n", hex_output);

    unsigned char binary_code[2048];
    size_t binary_size = hex_string_to_bytes(hex_output, binary_code, sizeof(binary_code));

    if (binary_size == 0) {
        fprintf(stderr, "[ Failure ] No valid hex sequences found to process.\n");
        curl_easy_cleanup(curl);
        return;
    }

    FILE *f = fopen(save_filename, "wb");
    if (f) {
        fwrite(binary_code, 1, binary_size, f);
        fclose(f);
        printf("[ Storage ] Saved block to disk -> %s (%zu bytes)\n", save_filename, binary_size);
    }

    void *exec_mem = mmap(NULL, binary_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("[ Engine ] Virtual memory mapping failed");
        curl_easy_cleanup(curl);
        return;
    }

    memcpy(exec_mem, binary_code, binary_size);

    BytecodeFunc JittedFunc = (BytecodeFunc)exec_mem;
    int a = 14, b = 3;
    printf("[ Engine ] Executing JIT function code block with default test inputs (%d, %d)...\n", a, b);
    int res_val = JittedFunc(a, b);
    printf("[ Engine ] Return code evaluated: %d\n", res_val);

    munmap(exec_mem, binary_size);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

void load_and_call_raw_file(const char *filename, int param1, int param2) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "[ Storage ] Target file missing or locked: %s\n", filename);
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        return;
    }

    unsigned char *buffer = malloc(size);
    size_t read_bytes = fread(buffer, 1, size, f);
    fclose(f);

    void *exec_mem = mmap(NULL, read_bytes, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("[ Engine ] Execution context page fault on mapping");
        free(buffer);
        return;
    }

    memcpy(exec_mem, buffer, read_bytes);
    free(buffer);

    BytecodeFunc LoadedFunc = (BytecodeFunc)exec_mem;
    printf("[ Engine ] Calling file-loaded bytecode: %s with inputs (%d, %d)...\n", filename, param1, param2);
    int res_val = LoadedFunc(param1, param2);
    printf("[ Engine ] Return code evaluated: %d\n", res_val);

    munmap(exec_mem, read_bytes);
}

int main(void) {
    char api_key[256] = {0};
    if (!load_api_key(api_key, sizeof(api_key))) {
        fprintf(stderr, "[ Critical ] API Authentication failed. Provide token via local file '%s' or through environment variables.\n", KEY_FILE_NAME);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    char user_prompt[1024];
    char target_bin[256];
    int test_a = 0, test_b = 0;

    printf("=== LLM JIT Compiler Prompt Shell ===\n");
    list_available_raw_files();

    // 1. Get user assembly instruction / prompt
    printf("Enter math instruction for the x86_64 function (e.g., 'Return param1 multiplied by param2 plus 5'):\n> ");
    if (!fgets(user_prompt, sizeof(user_prompt), stdin)) {
        goto cleanup;
    }
    user_prompt[strcspn(user_prompt, "\r\n")] = '\0'; // Clean newline

    // 2. Get target output filename
    printf("\nEnter output filename to save raw bytecode (e.g., 'my_func.raw'):\n> ");
    if (!fgets(target_bin, sizeof(target_bin), stdin)) {
        goto cleanup;
    }
    target_bin[strcspn(target_bin, "\r\n")] = '\0'; // Clean newline

    // Ensure it has .raw extension if user omitted it
    if (!strstr(target_bin, ".raw") && strlen(target_bin) < 250) {
        strcat(target_bin, ".raw");
    }

    // 3. Compile and execute
    printf("\n--- Processing Pipeline ---\n");
    generate_and_call_prompt(api_key, user_prompt, target_bin);

    // 4. Test execution on arbitrary custom parameters
    printf("\n--- Test Suite Reload ---\n");
    printf("Enter two integers to pass into your new raw binary file (separated by space):\n> ");
    if (scanf("%d %d", &test_a, &test_b) == 2) {
        load_and_call_raw_file(target_bin, test_a, test_b);
    } else {
        printf("[ Engine ] Invalid inputs. Skipping custom verification test.\n");
    }

cleanup:
    curl_global_cleanup();
    printf("\n[ System ] Pipeline session closed.\n");
    return 0;
}
