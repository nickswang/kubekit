#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#include "main.h"

const int MAX_TRIES = 10;

// Define the prefix to check for
const char *prefixToCheck = "debug";

char *processPodItemAndGetUpdatedJSON(cJSON *podItem, cJSON *root) {
    cJSON *cells = cJSON_GetObjectItem(podItem, "cells");

    if (cells != NULL) {
        cJSON *name = cJSON_GetArrayItem(cells, 0);
        cJSON *phase = cJSON_GetArrayItem(cells, 2);

        if (name != NULL && cJSON_IsString(name) && phase != NULL && cJSON_IsString(phase)) {
            // Check if the name begins with the specified prefix and the status is "Running"
            if (strncmp(name->valuestring, prefixToCheck, strlen(prefixToCheck)) == 0 &&
                strcmp(phase->valuestring, "Running") == 0) {
                return NULL;  // Signal to remove this item
            }
        }
    }

    return cJSON_Print(podItem);
}

char *processJSONBuffer(char *jsonBuffer, size_t bufferSize) {
    // Parse JSON
    cJSON *root = cJSON_Parse(jsonBuffer);
    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        cJSON_Delete(root); // Clean up in case of error
        return NULL;        // Signal an error
    }

    // Access the "items" array
    cJSON *items = cJSON_GetObjectItem(root, "rows");
    if (items != NULL && cJSON_IsArray(items)) {
        int arraySize = cJSON_GetArraySize(items);

        // Create a new array to collect items to keep
        cJSON *filteredItems = cJSON_CreateArray();

        for (int i = 0; i < arraySize; ++i) {
            cJSON *podItem = cJSON_GetArrayItem(items, i);
            char *updatedJsonBuffer = processPodItemAndGetUpdatedJSON(podItem, root);

            if (updatedJsonBuffer != NULL) {
                // Add the item to the new array
                cJSON_AddItemToArray(filteredItems, cJSON_Parse(updatedJsonBuffer));
            }

            // Clean up the updated JSON buffer
            free(updatedJsonBuffer);
        }

        // Replace the "items" array in the root object
        cJSON_ReplaceItemInObject(root, "rows", filteredItems);
    } else {
        cJSON_Delete(root);
        return NULL;  // Signal an error
    }

    // Convert the updated JSON structure back to a string
    char *updatedJsonBuffer = cJSON_PrintUnformatted(root);

    // Clean up cJSON objects
    cJSON_Delete(root);

    return updatedJsonBuffer;
}

char *handle_json(char *buf, size_t size) {
    char *new;

    new = processJSONBuffer(buf, size);
    if (new != NULL) {
        return new;
    }

    return buf;
}

int main() {
    int fd;
    ssize_t ret;
    char *buf, *new;
    size_t size;
    int i;

    size = JSON_BUF_SIZE;
    buf = malloc(size);
    if (buf == NULL) {
        perror("malloc");
        return -1;
    }

    i = 0;
    do {
        fd = open("/dev/" KUBE_JSON_FNAME, O_RDWR);
        sleep(1);
    } while (fd < 0 && i++ < MAX_TRIES);

    if (fd < 0) {
        perror("open");
        return -1;
    }

    while (1) {
        ret = read(fd, buf, size);
        new = handle_json(buf, ret);
        write(fd, new, strlen(new) + 1);

        if (new != buf) {
            free(new);
        }
    }

    free(buf);
    close(fd);
    return 0;
}
