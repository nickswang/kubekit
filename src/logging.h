#ifndef __LOGGING_H__
#define __LOGGING_H__

struct kubekit_msg {
    size_t len;
    char *msg;

    struct list_head list;
};

int kubekit_log_init(void);
void kubekit_log_free(void);
void kubekit_log(const char *msg, ...);

#endif
