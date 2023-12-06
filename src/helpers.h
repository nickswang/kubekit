#ifndef __HELPERS_H__
#define __HELPERS_H__

extern int kubekit_irq_num;
extern gate_desc *idt_table;

void enable_write_protection(void);
void disable_write_protection(void);
void idt_write_handler(int idt_table_idx, void *new_handler);
u64 idt_read_handler(int idt_table_idx);
int register_irq(void *handler);
inline void cleanup_idt(void);
inline u8 *read_file(char *filename);
inline ssize_t write_file(char *filename, u8 *buf, size_t size, loff_t pos);
char *get_path_from_task_struct(struct task_struct *task, char *buf);
void write_to_all_proc(
    char *filename,
    off_t offset,
    u8 *bytes,
    size_t size,
    u8 *prev
);
void write_to_all_lib(char *filename, off_t offset, u8 *bytes, size_t size);
int write_task_mem(struct task_struct *task, u8 *addr, u8 *bytes, size_t size);
u64 get_file_base_from_task_struct(struct task_struct *task, char *file);
struct vm_area_struct *get_vma_from_ptr(struct task_struct *task, u64 ptr);
u64 get_task_cr3(struct task_struct *task);
bool valid_stack(struct task_struct *task, u64 addr);
bool valid_return(struct task_struct *task, u64 addr);
int setup_entry_handler(void (*entry_handler));
void *get_sys_call_table(void);
char *full_path_to_file_user(
    struct task_struct *task,
    char *filename,
    unsigned int mode
);
bool task_env_allowed(struct task_struct *task);
char *extract_filename_from_full_path(char *s);
char *format_str(const char *fmt, ...);
char *file_from_fd(int fd);

#endif
