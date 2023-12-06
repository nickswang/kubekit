#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#include "logging.h"
#include "kubekit.h"

// maximum messages cutoff as we don't
// want it to grow infinitely
#define LOG_BUF_CUTOFF      5000

static size_t msg_num;

struct mutex kubekit_log_lock;

struct list_head kubekit_msg_list;
LIST_HEAD(kubekit_msg_list);

static struct cdev cdev;
static struct class *class;
static struct device *device;
dev_t dev_num;
bool initialized;

ssize_t kubekit_log_read(
    struct file *f,
    char __user *buf,
    size_t len,
    loff_t *off
);

static struct file_operations log_fops = {
    .owner = THIS_MODULE,
    .read = kubekit_log_read,
};

int kubekit_log_init(void) {
    initialized = false;

    if (alloc_chrdev_region(&dev_num, 0, 1, LOG_DEVICE_NAME) < 0) {
        return -1;
    }

    cdev_init(&cdev, &log_fops);
    if (cdev_add(&cdev, dev_num, 1) < 0) {
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    class = class_create(THIS_MODULE, LOG_DEVICE_NAME);
    if (IS_ERR(class)) {
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    device = device_create(class, NULL, dev_num, NULL, LOG_DEVICE_NAME);
    if (IS_ERR(device)) {
        class_destroy(class);
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    initialized = true;

    mutex_init(&kubekit_log_lock);
    msg_num = 0;

    return 0;
}

void kubekit_log_free(void) {
    struct kubekit_msg *msg, *tmp;

    if (initialized == false) {
        return;
    }

    device_destroy(class, dev_num);
    class_destroy(class);
    cdev_del(&cdev);
    unregister_chrdev_region(dev_num, 1);

    mutex_lock(&kubekit_log_lock);

    list_for_each_entry_safe(msg, tmp, &kubekit_msg_list, list) {
        list_del(&msg->list);

        kfree(msg->msg);
        kfree(msg);
    }

    mutex_unlock(&kubekit_log_lock);
}

void kubekit_log(const char *str, ...) {
    struct kubekit_msg *msg;
    char *buf;
    size_t msg_len;
    va_list args;

    if (initialized == false) {
        return;
    }

    va_start(args, str);
    msg_len = vsnprintf(NULL, 0, str, args);
    va_end(args);

    if (msg_len == 0) {
        return;
    }

    msg = kmalloc(sizeof(*msg), GFP_KERNEL);
    if (msg == NULL) {
        return;
    }

    buf = kmalloc(msg_len + 1, GFP_KERNEL);
    if (buf == NULL) {
        kfree(msg);
        return;
    }

    va_start(args, str);
    vsnprintf(buf, msg_len + 1, str, args);
    va_end(args);

    msg->msg = buf;
    msg->len = msg_len;

    mutex_lock(&kubekit_log_lock);

    list_add_tail(&msg->list, &kubekit_msg_list);
    if (msg_num < LOG_BUF_CUTOFF) {
        msg_num++;
    } else {
        msg = list_first_entry(&kubekit_msg_list, struct kubekit_msg, list);
        list_del(&msg->list);

        kfree(msg->msg);
        kfree(msg);
    }

    mutex_unlock(&kubekit_log_lock);
}

ssize_t kubekit_log_read(struct file *f,
                         char __user *buf,
                         size_t len,
                         loff_t *off) {
    size_t skipped;
    size_t copied;
    size_t curr_amnt;
    struct kubekit_msg *msg;
    ssize_t ret;
    char *src;

    src = kmalloc(len, GFP_KERNEL);
    if (src == NULL) {
        return 0;
    }

    skipped = 0;
    copied = 0;
    mutex_lock(&kubekit_log_lock);

    list_for_each_entry(msg, &kubekit_msg_list, list) {
        if (skipped + msg->len < *off) {
            skipped += msg->len;
            continue;
        }

        if (copied >= len) {
            break;
        }

        curr_amnt = min(msg->len - ((size_t)*off - skipped), len - copied);
        memcpy(src + copied, msg->msg + (*off - skipped), curr_amnt);
        copied += curr_amnt;
        skipped = *off;
    }

    mutex_unlock(&kubekit_log_lock);
    *off += copied;

    ret = copy_to_user(buf, src, copied);
    kfree(src);
    return copied - ret;
}
