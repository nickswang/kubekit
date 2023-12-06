#ifndef __SYSCALL_HOOKS_H__
#define __SYSCALL_HOOKS_H__

asmlinkage long open_hook(struct pt_regs *regs);
asmlinkage long openat_hook(struct pt_regs *regs);
asmlinkage long stat_hook(struct pt_regs *regs);
asmlinkage long statx_hook(struct pt_regs *regs);
asmlinkage long getdents64_hook(struct pt_regs *regs);
asmlinkage long unlink_hook(struct pt_regs *regs);
asmlinkage long unlinkat_hook(struct pt_regs *regs);
asmlinkage long read_hook(struct pt_regs *regs);

#endif
