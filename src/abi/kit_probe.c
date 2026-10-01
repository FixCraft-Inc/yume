#define _POSIX_C_SOURCE 200809L

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Opens a sealed kit through the public C ABI v1 and compares it with the
 * directory `yume --seal-kit` sealed. The Python fixture provisions the kit
 * and seals it with the yume program, so both ends of sealed kit 1 are the
 * shipped ones.
 */

#include <yume/yume.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* The largest sealed kit: salt, nonce, length, 1 MiB of content, one padding
 * block and the tag (docs/protocol/SEALED_KIT_1.md). */
#define MAX_SEALED_BYTES (16u + 12u + 4u + 1024u * 1024u + 1024u + 16u)

static unsigned char* read_file(const char* path, size_t* out_size) {
    FILE* file = fopen(path, "rb");
    unsigned char* buffer = NULL;
    long size = 0;
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) goto fail;
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) goto fail;
    buffer = (unsigned char*)malloc((size_t)size + 1u);
    if (buffer == NULL) goto fail;
    if (fread(buffer, 1u, (size_t)size, file) != (size_t)size) goto fail;
    *out_size = (size_t)size;
    fclose(file);
    return buffer;

fail:
    free(buffer);
    fclose(file);
    return NULL;
}

static int expect(yume_status actual, yume_status wanted, const char* what) {
    if (actual == wanted) return 1;
    fprintf(stderr, "%s: status %d, expected %d\n", what, (int)actual,
            (int)wanted);
    return 0;
}

/* A refused kit publishes no handle and says why on the runtime. */
static int expect_refused(yume_runtime* runtime, const unsigned char* sealed,
                          size_t sealed_size, const char* code,
                          yume_status wanted, const char* what) {
    yume_kit* kit = (yume_kit*)runtime;
    yume_diagnostic diagnostic;
    const yume_status status =
        yume_kit_open(runtime, sealed, sealed_size, code,
                      code == NULL ? 0u : strlen(code), &kit);
    if (!expect(status, wanted, what)) {
        yume_kit_destroy(status == YUME_STATUS_OK ? kit : NULL);
        return 0;
    }
    if (kit != NULL) {
        fprintf(stderr, "%s: a refused kit published a handle\n", what);
        return 0;
    }
    memset(&diagnostic, 0, sizeof(diagnostic));
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    if (yume_handle_get_diagnostic(runtime, &diagnostic, sizeof(diagnostic)) !=
            YUME_STATUS_OK ||
        diagnostic.status != wanted || diagnostic.message[0] == '\0') {
        fprintf(stderr, "%s: the runtime does not say why\n", what);
        return 0;
    }
    return 1;
}

static int file_matches(const char* directory, const yume_kit_file* file) {
    char path[4096];
    unsigned char* expected = NULL;
    size_t expected_size = 0u;
    struct stat info;
    int same = 0;
    if (file->path.size == 0u || file->path.size > 64u ||
        snprintf(path, sizeof(path), "%s/%.*s", directory, (int)file->path.size,
                 file->path.data) >= (int)sizeof(path)) {
        fprintf(stderr, "a kit path is empty or too long\n");
        return 0;
    }
    expected = read_file(path, &expected_size);
    if (expected == NULL || stat(path, &info) != 0) {
        fprintf(stderr, "the kit names a file the directory lacks: %s\n", path);
        free(expected);
        return 0;
    }
    same =
        expected_size == file->size &&
        (file->size == 0u || memcmp(expected, file->data, file->size) == 0) &&
        (file->executable != 0u) == ((info.st_mode & S_IXUSR) != 0);
    if (!same)
        fprintf(stderr, "a kit file differs from its source: %s\n", path);
    free(expected);
    return same;
}

/* Every file as it was sealed, in path order, with yume.json among them. */
static int check_opened(yume_runtime* runtime, const yume_kit* kit,
                        const char* directory, size_t expected_files) {
    const size_t count = yume_kit_file_count(kit);
    char previous[65] = "";
    int has_config = 0;
    yume_kit_file file;
    size_t index = 0u;
    if (count == 0u || count > 32u || count != expected_files) {
        fprintf(stderr, "the kit holds %zu files, expected %zu\n", count,
                expected_files);
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        char name[65];
        memset(&file, 0, sizeof(file));
        file.struct_size = sizeof(file);
        file.abi_version = YUME_ABI_VERSION;
        if (!expect(yume_kit_get_file(kit, index, &file, sizeof(file)),
                    YUME_STATUS_OK, "kit file") ||
            !file_matches(directory, &file)) {
            return 0;
        }
        memcpy(name, file.path.data, file.path.size);
        name[file.path.size] = '\0';
        if (strcmp(previous, name) >= 0) {
            fprintf(stderr, "kit files are not in path order\n");
            return 0;
        }
        strcpy(previous, name);
        if (strcmp(name, "yume.json") == 0) {
            yume_config* config = NULL;
            has_config = 1;
            /* The kit's own configuration is one this library accepts. */
            if (!expect(yume_config_parse_json(runtime, file.data, file.size,
                                               &config),
                        YUME_STATUS_OK, "the kit's yume.json") ||
                yume_config_role(config) != YUME_ROLE_CLIENT) {
                yume_config_destroy(config);
                return 0;
            }
            yume_config_destroy(config);
        }
    }
    if (!has_config) {
        fprintf(stderr, "the kit has no yume.json\n");
        return 0;
    }
    memset(&file, 0, sizeof(file));
    file.struct_size = sizeof(file);
    file.abi_version = YUME_ABI_VERSION;
    if (!expect(yume_kit_get_file(kit, count, &file, sizeof(file)),
                YUME_STATUS_NOT_FOUND, "a file past the last") ||
        !expect(yume_kit_get_file(kit, 0u, NULL, sizeof(file)),
                YUME_STATUS_INVALID_ARGUMENT, "a file without storage")) {
        return 0;
    }
    file.struct_size = sizeof(file) - 1u;
    return expect(yume_kit_get_file(kit, 0u, &file, sizeof(file)),
                  YUME_STATUS_INVALID_ARGUMENT, "a truncated file struct");
}

int main(int argc, char** argv) {
    yume_runtime_options options;
    yume_runtime* runtime = NULL;
    yume_kit* kit = NULL;
    unsigned char* sealed = NULL;
    unsigned char* changed = NULL;
    unsigned char* oversized = NULL;
    size_t sealed_size = 0u;
    size_t expected_files = 0u;
    char typed[128];
    char wrong[128];
    size_t index = 0u;
    size_t out = 0u;
    int result = 1;

    if (argc != 5) {
        fprintf(stderr, "usage: %s SEALED CODE KIT_DIRECTORY FILE_COUNT\n",
                argv[0]);
        return 2;
    }
    expected_files = (size_t)strtoul(argv[4], NULL, 10);
    if (strlen(argv[2]) != 29u) {
        fprintf(stderr, "the code is not in its displayed form\n");
        return 2;
    }
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.config_base_dir = argv[3];
    if (!expect(yume_runtime_create(&options, &runtime), YUME_STATUS_OK,
                "runtime create")) {
        return 1;
    }
    sealed = read_file(argv[1], &sealed_size);
    changed = (unsigned char*)malloc(sealed_size == 0u ? 1u : sealed_size);
    oversized = (unsigned char*)calloc(1u, MAX_SEALED_BYTES + 1u);
    if (sealed == NULL || changed == NULL || oversized == NULL ||
        sealed_size < 64u) {
        fprintf(stderr, "cannot read the sealed kit\n");
        goto cleanup;
    }

    /* The code as displayed, with its separators. */
    if (!expect(yume_kit_open(runtime, sealed, sealed_size, argv[2],
                              strlen(argv[2]), &kit),
                YUME_STATUS_OK, "open with the displayed code") ||
        !check_opened(runtime, kit, argv[3], expected_files)) {
        goto cleanup;
    }
    yume_kit_destroy(kit);
    kit = NULL;

    /* The code as a person types it: lower case, spaces, no separators. */
    for (index = 0u; argv[2][index] != '\0'; ++index) {
        char letter = argv[2][index];
        if (letter == '-') {
            if (index % 2u == 0u) typed[out++] = ' ';
            continue;
        }
        if (letter >= 'A' && letter <= 'Z') letter = (char)(letter - 'A' + 'a');
        typed[out++] = letter;
    }
    typed[out] = '\0';
    if (!expect(yume_kit_open(runtime, sealed, sealed_size, typed,
                              strlen(typed), &kit),
                YUME_STATUS_OK, "open with the typed code") ||
        yume_kit_file_count(kit) != expected_files) {
        goto cleanup;
    }
    yume_kit_destroy(kit);
    kit = NULL;

    /* One character of the code changed to another code character. */
    strcpy(wrong, argv[2]);
    wrong[0] = wrong[0] == '7' ? '8' : '7';
    memcpy(changed, sealed, sealed_size);
    changed[sealed_size / 2u] ^= 0x01u;
    if (!expect_refused(runtime, sealed, sealed_size, wrong,
                        YUME_STATUS_PERMISSION_DENIED, "a wrong code") ||
        !expect_refused(runtime, changed, sealed_size, argv[2],
                        YUME_STATUS_PERMISSION_DENIED, "a changed file") ||
        !expect_refused(runtime, sealed, sealed_size - 1u, argv[2],
                        YUME_STATUS_PERMISSION_DENIED,
                        "a file of another shape") ||
        !expect_refused(runtime, sealed, sealed_size, "7777-7777",
                        YUME_STATUS_INVALID_ARGUMENT, "a short code") ||
        !expect_refused(
            runtime, sealed, sealed_size, "UUUUU-UUUUU-UUUUU-UUUUU-UUUUU",
            YUME_STATUS_INVALID_ARGUMENT, "a code outside its alphabet") ||
        !expect_refused(runtime, oversized, MAX_SEALED_BYTES + 1u, argv[2],
                        YUME_STATUS_RESOURCE_EXHAUSTED, "an oversized file") ||
        !expect_refused(runtime, sealed, 0u, argv[2],
                        YUME_STATUS_INVALID_ARGUMENT, "an empty file") ||
        !expect_refused(runtime, NULL, sealed_size, argv[2],
                        YUME_STATUS_INVALID_ARGUMENT, "no file") ||
        !expect_refused(runtime, sealed, sealed_size, NULL,
                        YUME_STATUS_INVALID_ARGUMENT, "no code")) {
        goto cleanup;
    }
    if (!expect(yume_kit_open(runtime, sealed, sealed_size, argv[2],
                              strlen(argv[2]), NULL),
                YUME_STATUS_INVALID_ARGUMENT, "no output handle") ||
        !expect(yume_kit_open(NULL, sealed, sealed_size, argv[2],
                              strlen(argv[2]), &kit),
                YUME_STATUS_INVALID_ARGUMENT, "no runtime") ||
        yume_kit_file_count(NULL) != 0u) {
        goto cleanup;
    }
    yume_kit_destroy(NULL);

    result = 0;
    printf("C ABI v1 sealed kit integration passed\n");

cleanup:
    yume_kit_destroy(kit);
    free(sealed);
    free(changed);
    free(oversized);
    yume_runtime_destroy(runtime);
    return result;
}
