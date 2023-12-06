#ifndef __MAIN_H__
#define __MAIN_H__

#define KUBE_JSON_FNAME     "kube_json"
#define JSON_HANDLER_BIN    "json_handler.out"

#define JSON_BUF_SIZE       (4096 * 256)

struct json_resp {
    size_t size;
    size_t new_size;
    size_t max_size;
    bool done;

    char buf[];
};


#endif
