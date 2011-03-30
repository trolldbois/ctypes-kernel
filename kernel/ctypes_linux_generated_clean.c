struct sched_param {
 int sched_priority;
};
typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __signed__ int __s32;
typedef unsigned int __u32;
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef unsigned short umode_t;
typedef u64 dma64_addr_t;
typedef u64 dma_addr_t;
struct ftrace_branch_data {
 const char *func;
 const char *file;
 unsigned line;
 union {
  struct {
   unsigned long correct;
   unsigned long incorrect;
  };
  struct {
   unsigned long miss;
   unsigned long hit;
  };
  unsigned long miss_hit[2];
 };
};
typedef struct {
 unsigned long fds_bits [(1024/(8 * sizeof(unsigned long)))];
} __kernel_fd_set;
typedef void (*__kernel_sighandler_t)(int);

typedef int __kernel_key_t;
typedef int __kernel_mqd_t;
typedef unsigned long __kernel_ino_t;
typedef unsigned short __kernel_mode_t;
typedef unsigned short __kernel_nlink_t;
typedef long __kernel_off_t;
typedef int __kernel_pid_t;
typedef unsigned short __kernel_ipc_pid_t;
typedef unsigned short __kernel_uid_t;
typedef unsigned short __kernel_gid_t;
typedef unsigned int __kernel_size_t;
typedef int __kernel_ssize_t;
typedef int __kernel_ptrdiff_t;
typedef long __kernel_time_t;
typedef long __kernel_suseconds_t;
typedef long __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef int __kernel_daddr_t;
typedef char * __kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
typedef unsigned short __kernel_old_dev_t;
typedef long long __kernel_loff_t;
typedef struct {
 int val[2];
} __kernel_fsid_t;
typedef __u32 __kernel_dev_t;
typedef __kernel_fd_set fd_set;
typedef __kernel_dev_t dev_t;
typedef __kernel_ino_t ino_t;
typedef __kernel_mode_t mode_t;
typedef __kernel_nlink_t nlink_t;
typedef __kernel_off_t off_t;
typedef __kernel_pid_t pid_t;
typedef __kernel_daddr_t daddr_t;
typedef __kernel_key_t key_t;
typedef __kernel_suseconds_t suseconds_t;
typedef __kernel_timer_t timer_t;
typedef __kernel_clockid_t clockid_t;
typedef __kernel_mqd_t mqd_t;
typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef __kernel_uid16_t uid16_t;
typedef __kernel_gid16_t gid16_t;
typedef unsigned long uintptr_t;
typedef __kernel_old_uid_t old_uid_t;
typedef __kernel_old_gid_t old_gid_t;
typedef __kernel_loff_t loff_t;
typedef __kernel_size_t size_t;
typedef __kernel_ssize_t ssize_t;
typedef __kernel_ptrdiff_t ptrdiff_t;
typedef __kernel_time_t time_t;
typedef __kernel_clock_t clock_t;
typedef __kernel_caddr_t caddr_t;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef unsigned char unchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef __u8 u_int8_t;
typedef __s8 int8_t;
typedef __u16 u_int16_t;
typedef __s16 int16_t;
typedef __u32 u_int32_t;
typedef __s32 int32_t;
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __u64 u_int64_t;
typedef __s64 int64_t;
typedef u64 sector_t;
typedef u64 blkcnt_t;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;
typedef unsigned gfp_t;
typedef unsigned fmode_t;
typedef u64 phys_addr_t;
typedef phys_addr_t resource_size_t;
typedef struct {
 int counter;
} atomic_t;
struct ustat {
 __kernel_daddr_t f_tfree;
 __kernel_ino_t f_tinode;
 char f_fname[6];
 char f_fpack[6];
};
struct task_struct;
typedef struct __user_cap_header_struct {
 __u32 version;
 int pid;
} *cap_user_header_t;
typedef struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
} *cap_user_data_t;
struct vfs_cap_data {
 __le32 magic_etc;
 struct {
  __le32 permitted;
  __le32 inheritable;
 } data[2];
};
// supprimed extern
typedef struct kernel_cap_struct {
 __u32 cap[2];
} kernel_cap_t;
struct cpu_vfs_cap_data {
 __u32 magic_etc;
 kernel_cap_t permitted;
 kernel_cap_t inheritable;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct dentry;
// supprimed extern
typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct alt_instr {
 u8 *instr;
 u8 *replacement;
 u8 cpuid;
 u8 instrlen;
 u8 replacementlen;
 u8 pad1;
};
// supprimed extern
// supprimed extern
struct module;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
struct paravirt_patch_site;
void apply_paravirt(struct paravirt_patch_site *start,
      struct paravirt_patch_site *end);
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
struct _ddebug {
 const char *modname;
 const char *function;
 const char *filename;
 const char *format;
 char primary_hash;
 char secondary_hash;
 unsigned int lineno:24;
 unsigned int flags:8;
} __attribute__((aligned(8)));
int ddebug_add_module(struct _ddebug *tab, unsigned int n,
    const char *modname);
// supprimed function
struct bug_entry {
 unsigned long bug_addr;
 const char *file;
 unsigned short line;
 unsigned short flags;
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
struct completion;
struct pt_regs;
struct user;
// supprimed extern
  static inline void __might_sleep(const char *file, int line,
       int preempt_offset) { }
// supprimed function
extern struct atomic_notifier_head panic_notifier_list;
// supprimed extern
 void panic(const char * fmt, ...)
 __attribute__ ((noreturn, format (printf, 1, 2))) __attribute__((__cold__));
// supprimed extern
// supprimed extern
// supprimed extern
 void do_exit(long error_code)
 __attribute__((noreturn));
 void complete_and_exit(struct completion *, long)
 __attribute__((noreturn));
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct pid;
extern struct pid *session_of_pgrp(struct pid *pgrp);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void log_buf_kexec_setup(void);
// supprimed extern
// supprimed extern
// supprimed extern
unsigned long int_sqrt(unsigned long);
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern enum system_states {
 SYSTEM_BOOTING,
 SYSTEM_RUNNING,
 SYSTEM_HALT,
 SYSTEM_POWER_OFF,
 SYSTEM_RESTART,
 SYSTEM_SUSPEND_DISK,
} system_state;
// supprimed extern
enum {
 DUMP_PREFIX_NONE,
 DUMP_PREFIX_ADDRESS,
 DUMP_PREFIX_OFFSET
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
void tracing_on(void);
void tracing_off(void);
void tracing_off_permanent(void);
int tracing_is_on(void);
enum ftrace_dump_mode {
 DUMP_NONE,
 DUMP_ALL,
 DUMP_ORIG,
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
static inline void __attribute__ ((format (printf, 1, 2)))
____trace_printk_check_format(const char *fmt, ...)
{
}
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct sysinfo;
// supprimed extern
struct sysinfo {
 long uptime;
 unsigned long loads[3];
 unsigned long totalram;
 unsigned long freeram;
 unsigned long sharedram;
 unsigned long bufferram;
 unsigned long totalswap;
 unsigned long freeswap;
 unsigned short procs;
 unsigned short pad;
 unsigned long totalhigh;
 unsigned long freehigh;
 unsigned int mem_unit;
 char _f[20-2*sizeof(long)-sizeof(int)];
};
struct timespec;
struct compat_timespec;
struct restart_block {
 long (*fn)(struct restart_block *);
 union {
  struct {
   unsigned long arg0, arg1, arg2, arg3;
  };
  struct {
   u32 *uaddr;
   u32 val;
   u32 flags;
   u32 bitset;
   u64 time;
   u32 *uaddr2;
  } futex;
  struct {
   clockid_t index;
   struct timespec *rmtp;
   u64 expires;
  } nanosleep;
  struct {
   struct pollfd *ufds;
   int nfds;
   int has_timeout;
   unsigned long tv_sec;
   unsigned long tv_nsec;
  } poll;
 };
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
void *memmove(void *dest, const void *src, size_t n);
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
size_t strlcpy(char *, const char *, size_t);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
int vbin_printf(u32 *bin_buf, size_t size, const char *fmt, va_list args);
int bstr_printf(char *buf, size_t size, const char *fmt, const u32 *bin_buf);
int bprintf(u32 *bin_buf, size_t size, const char *fmt, ...) __attribute__((format(printf,3,4)));
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
struct page;
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
struct task_struct;
struct exec_domain;
struct task_struct;
struct mm_struct;
struct vm86_regs {
 long ebx;
 long ecx;
 long edx;
 long esi;
 long edi;
 long ebp;
 long eax;
 long __null_ds;
 long __null_es;
 long __null_fs;
 long __null_gs;
 long orig_eax;
 long eip;
 unsigned short cs, __csh;
 long eflags;
 long esp;
 unsigned short ss, __ssh;
 unsigned short es, __esh;
 unsigned short ds, __dsh;
 unsigned short fs, __fsh;
 unsigned short gs, __gsh;
};
struct revectored_struct {
 unsigned long __map[8];
};
struct vm86_struct {
 struct vm86_regs regs;
 unsigned long flags;
 unsigned long screen_bitmap;
 unsigned long cpu_type;
 struct revectored_struct int_revectored;
 struct revectored_struct int21_revectored;
};
struct vm86plus_info_struct {
 unsigned long force_return_for_pic:1;
 unsigned long vm86dbg_active:1;
 unsigned long vm86dbg_TFpendig:1;
 unsigned long unused:28;
 unsigned long is_vm86pus:1;
 unsigned char vm86dbg_intxxtab[32];
};
struct vm86plus_struct {
 struct vm86_regs regs;
 unsigned long flags;
 unsigned long screen_bitmap;
 unsigned long cpu_type;
 struct revectored_struct int_revectored;
 struct revectored_struct int21_revectored;
 struct vm86plus_info_struct vm86plus;
};
// supprimed extern
struct pt_regs {
 unsigned long bx;
 unsigned long cx;
 unsigned long dx;
 unsigned long si;
 unsigned long di;
 unsigned long bp;
 unsigned long ax;
 unsigned long ds;
 unsigned long es;
 unsigned long fs;
 unsigned long gs;
 unsigned long orig_ax;
 unsigned long ip;
 unsigned long cs;
 unsigned long flags;
 unsigned long sp;
 unsigned long ss;
};
typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);
// supprimed extern
// supprimed extern
typedef void (*ctor_fn_t)(void);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void setup_arch(char **);
void prepare_namespace(void);
// supprimed extern
// supprimed extern
struct obs_kernel_param {
 const char *str;
 int (*setup_func)(char *);
 int early;
};
void __attribute__ ((__section__(".init.text"))) __attribute__((__cold__)) __attribute__((no_instrument_function)) parse_early_param(void);
void __attribute__ ((__section__(".init.text"))) __attribute__((__cold__)) __attribute__((no_instrument_function)) parse_early_options(char *cmdline);
struct cpuinfo_x86;
struct task_struct;
// supprimed extern
// supprimed extern
// supprimed extern
void signal_fault(struct pt_regs *regs, void *frame, char *where);
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
struct user_desc;
// supprimed extern
// supprimed extern
struct kernel_vm86_regs {
 struct pt_regs pt;
 unsigned short es, __esh;
 unsigned short ds, __dsh;
 unsigned short fs, __fsh;
 unsigned short gs, __gsh;
};
struct kernel_vm86_struct {
 struct kernel_vm86_regs regs;
 unsigned long flags;
 unsigned long screen_bitmap;
 unsigned long cpu_type;
 struct revectored_struct int_revectored;
 struct revectored_struct int21_revectored;
 struct vm86plus_info_struct vm86plus;
 struct pt_regs *regs32;
};
void handle_vm86_fault(struct kernel_vm86_regs *, long);
int handle_vm86_trap(struct kernel_vm86_regs *, long, int);
struct pt_regs *save_v86_state(struct kernel_vm86_regs *);
struct task_struct;
void release_vm86_irqs(struct task_struct *);
struct math_emu_info {
 long ___orig_eip;
 union {
  struct pt_regs *regs;
  struct kernel_vm86_regs *vm86;
 };
};
struct _fpx_sw_bytes {
 __u32 magic1;
 __u32 extended_size;
 __u64 xstate_bv;
 __u32 xstate_size;
 __u32 padding[7];
};
struct _fpreg {
 unsigned short significand[4];
 unsigned short exponent;
};
struct _fpxreg {
 unsigned short significand[4];
 unsigned short exponent;
 unsigned short padding[3];
};
struct _xmmreg {
 unsigned long element[4];
};
struct _fpstate {
 unsigned long cw;
 unsigned long sw;
 unsigned long tag;
 unsigned long ipoff;
 unsigned long cssel;
 unsigned long dataoff;
 unsigned long datasel;
 struct _fpreg _st[8];
 unsigned short status;
 unsigned short magic;
 unsigned long _fxsr_env[6];
 unsigned long mxcsr;
 unsigned long reserved;
 struct _fpxreg _fxsr_st[8];
 struct _xmmreg _xmm[8];
 unsigned long padding1[44];
 union {
  unsigned long padding2[12];
  struct _fpx_sw_bytes sw_reserved;
 };
};
struct sigcontext {
 unsigned short gs, __gsh;
 unsigned short fs, __fsh;
 unsigned short es, __esh;
 unsigned short ds, __dsh;
 unsigned long di;
 unsigned long si;
 unsigned long bp;
 unsigned long sp;
 unsigned long bx;
 unsigned long dx;
 unsigned long cx;
 unsigned long ax;
 unsigned long trapno;
 unsigned long err;
 unsigned long ip;
 unsigned short cs, __csh;
 unsigned long flags;
 unsigned long sp_at_signal;
 unsigned short ss, __ssh;
 void *fpstate;
 unsigned long oldmask;
 unsigned long cr2;
};
struct _xsave_hdr {
 __u64 xstate_bv;
 __u64 reserved1[2];
 __u64 reserved2[5];
};
struct _ymmh_state {
 __u32 ymmh_space[64];
};
struct _xstate {
 struct _fpstate fpstate;
 struct _xsave_hdr xstate_hdr;
 struct _ymmh_state ymmh;
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct task_struct;
// supprimed extern
// supprimed function
// supprimed extern
struct __xchg_dummy {
 unsigned long a[100];
};
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef u64 pteval_t;
typedef u64 pmdval_t;
typedef u64 pudval_t;
typedef u64 pgdval_t;
typedef u64 pgprotval_t;
typedef union {
 struct {
  unsigned long pte_low, pte_high;
 };
 pteval_t pte;
} pte_t;
// supprimed extern
typedef struct pgprot { pgprotval_t pgprot; } pgprot_t;
typedef struct { pgdval_t pgd; } pgd_t;
// supprimed function
// supprimed function
// supprimed function
typedef struct { pgd_t pgd; } pud_t;
// supprimed function
// supprimed function
typedef struct { pmdval_t pmd; } pmd_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef struct page *pgtable_t;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct file;
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
                              unsigned long size, pgprot_t vma_prot);
int phys_mem_access_prot_allowed(struct file *file, unsigned long pfn,
                              unsigned long size, pgprot_t *vma_prot);
void set_pte_vaddr(unsigned long vaddr, pte_t pte);
// supprimed extern
// supprimed extern
struct seq_file;
// supprimed extern
enum {
 PG_LEVEL_NONE,
 PG_LEVEL_4K,
 PG_LEVEL_2M,
 PG_LEVEL_1G,
 PG_LEVEL_NUM
};
// supprimed extern
// supprimed extern
struct desc_struct {
 union {
  struct {
   unsigned int a;
   unsigned int b;
  };
  struct {
   u16 limit0;
   u16 base0;
   unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
   unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
  };
 };
} __attribute__((packed));
enum {
 GATE_INTERRUPT = 0xE,
 GATE_TRAP = 0xF,
 GATE_CALL = 0xC,
 GATE_TASK = 0x5,
};
struct gate_struct64 {
 u16 offset_low;
 u16 segment;
 unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
 u16 offset_middle;
 u32 offset_high;
 u32 zero1;
} __attribute__((packed));
enum {
 DESC_TSS = 0x9,
 DESC_LDT = 0x2,
 DESCTYPE_S = 0x10,
};
struct ldttss_desc64 {
 u16 limit0;
 u16 base0;
 unsigned base1 : 8, type : 5, dpl : 2, p : 1;
 unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
 u32 base3;
 u32 zero1;
} __attribute__((packed));
typedef struct desc_struct gate_desc;
typedef struct desc_struct ldt_desc;
typedef struct desc_struct tss_desc;
struct desc_ptr {
 unsigned short size;
 unsigned long address;
} __attribute__((packed)) ;
enum km_type {
 KM_BOUNCE_READ,
 KM_SKB_SUNRPC_DATA,
 KM_SKB_DATA_SOFTIRQ,
 KM_USER0,
 KM_USER1,
 KM_BIO_SRC_IRQ,
 KM_BIO_DST_IRQ,
 KM_PTE0,
 KM_PTE1,
 KM_IRQ0,
 KM_IRQ1,
 KM_SOFTIRQ0,
 KM_SOFTIRQ1,
 KM_SYNC_ICACHE,
 KM_SYNC_DCACHE,
 KM_UML_USERCOPY,
 KM_IRQ_PTE,
 KM_NMI,
 KM_NMI_PTE,
 KM_KDB,
 KM_TYPE_NR
};
struct page;
struct thread_struct;
struct desc_ptr;
struct tss_struct;
struct mm_struct;
struct desc_struct;
struct task_struct;
struct cpumask;
struct paravirt_callee_save {
 void *func;
};
struct pv_info {
 unsigned int kernel_rpl;
 int shared_kernel_pmd;
 int paravirt_enabled;
 const char *name;
};
struct pv_init_ops {
 unsigned (*patch)(u8 type, u16 clobber, void *insnbuf,
     unsigned long addr, unsigned len);
};
struct pv_lazy_ops {
 void (*enter)(void);
 void (*leave)(void);
};
struct pv_time_ops {
 unsigned long long (*sched_clock)(void);
 unsigned long (*get_tsc_khz)(void);
};
struct pv_cpu_ops {
 unsigned long (*get_debugreg)(int regno);
 void (*set_debugreg)(int regno, unsigned long value);
 void (*clts)(void);
 unsigned long (*read_cr0)(void);
 void (*write_cr0)(unsigned long);
 unsigned long (*read_cr4_safe)(void);
 unsigned long (*read_cr4)(void);
 void (*write_cr4)(unsigned long);
 void (*load_tr_desc)(void);
 void (*load_gdt)(const struct desc_ptr *);
 void (*load_idt)(const struct desc_ptr *);
 void (*store_gdt)(struct desc_ptr *);
 void (*store_idt)(struct desc_ptr *);
 void (*set_ldt)(const void *desc, unsigned entries);
 void (*load_user_cs_desc)(int cpu, struct mm_struct *mm);
 unsigned long (*store_tr)(void);
 void (*load_tls)(struct thread_struct *t, unsigned int cpu);
 void (*write_ldt_entry)(struct desc_struct *ldt, int entrynum,
    const void *desc);
 void (*write_gdt_entry)(struct desc_struct *,
    int entrynum, const void *desc, int size);
 void (*write_idt_entry)(gate_desc *,
    int entrynum, const gate_desc *gate);
 void (*alloc_ldt)(struct desc_struct *ldt, unsigned entries);
 void (*free_ldt)(struct desc_struct *ldt, unsigned entries);
 void (*load_sp0)(struct tss_struct *tss, struct thread_struct *t);
 void (*set_iopl_mask)(unsigned mask);
 void (*wbinvd)(void);
 void (*io_delay)(void);
 void (*cpuid)(unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx);
 u64 (*read_msr)(unsigned int msr, int *err);
 int (*rdmsr_regs)(u32 *regs);
 int (*write_msr)(unsigned int msr, unsigned low, unsigned high);
 int (*wrmsr_regs)(u32 *regs);
 u64 (*read_tsc)(void);
 u64 (*read_pmc)(int counter);
 unsigned long long (*read_tscp)(unsigned int *aux);
 void (*irq_enable_sysexit)(void);
 void (*usergs_sysret64)(void);
 void (*usergs_sysret32)(void);
 void (*iret)(void);
 void (*swapgs)(void);
 void (*start_context_switch)(struct task_struct *prev);
 void (*end_context_switch)(struct task_struct *next);
};
struct pv_irq_ops {
 struct paravirt_callee_save save_fl;
 struct paravirt_callee_save restore_fl;
 struct paravirt_callee_save irq_disable;
 struct paravirt_callee_save irq_enable;
 void (*safe_halt)(void);
 void (*halt)(void);
};
struct pv_apic_ops {
 void (*startup_ipi_hook)(int phys_apicid,
     unsigned long start_eip,
     unsigned long start_esp);
};
struct pv_mmu_ops {
 unsigned long (*read_cr2)(void);
 void (*write_cr2)(unsigned long);
 unsigned long (*read_cr3)(void);
 void (*write_cr3)(unsigned long);
 void (*activate_mm)(struct mm_struct *prev,
       struct mm_struct *next);
 void (*dup_mmap)(struct mm_struct *oldmm,
    struct mm_struct *mm);
 void (*exit_mmap)(struct mm_struct *mm);
 void (*flush_tlb_user)(void);
 void (*flush_tlb_kernel)(void);
 void (*flush_tlb_single)(unsigned long addr);
 void (*flush_tlb_others)(const struct cpumask *cpus,
     struct mm_struct *mm,
     unsigned long va);
 int (*pgd_alloc)(struct mm_struct *mm);
 void (*pgd_free)(struct mm_struct *mm, pgd_t *pgd);
 void (*alloc_pte)(struct mm_struct *mm, unsigned long pfn);
 void (*alloc_pmd)(struct mm_struct *mm, unsigned long pfn);
 void (*alloc_pmd_clone)(unsigned long pfn, unsigned long clonepfn, unsigned long start, unsigned long count);
 void (*alloc_pud)(struct mm_struct *mm, unsigned long pfn);
 void (*release_pte)(unsigned long pfn);
 void (*release_pmd)(unsigned long pfn);
 void (*release_pud)(unsigned long pfn);
 void (*set_pte)(pte_t *ptep, pte_t pteval);
 void (*set_pte_at)(struct mm_struct *mm, unsigned long addr,
      pte_t *ptep, pte_t pteval);
 void (*set_pmd)(pmd_t *pmdp, pmd_t pmdval);
 void (*pte_update)(struct mm_struct *mm, unsigned long addr,
      pte_t *ptep);
 void (*pte_update_defer)(struct mm_struct *mm,
     unsigned long addr, pte_t *ptep);
 pte_t (*ptep_modify_prot_start)(struct mm_struct *mm, unsigned long addr,
     pte_t *ptep);
 void (*ptep_modify_prot_commit)(struct mm_struct *mm, unsigned long addr,
     pte_t *ptep, pte_t pte);
 struct paravirt_callee_save pte_val;
 struct paravirt_callee_save make_pte;
 struct paravirt_callee_save pgd_val;
 struct paravirt_callee_save make_pgd;
 void (*set_pte_atomic)(pte_t *ptep, pte_t pteval);
 void (*pte_clear)(struct mm_struct *mm, unsigned long addr,
     pte_t *ptep);
 void (*pmd_clear)(pmd_t *pmdp);
 void (*set_pud)(pud_t *pudp, pud_t pudval);
 struct paravirt_callee_save pmd_val;
 struct paravirt_callee_save make_pmd;
 struct pv_lazy_ops lazy_mode;
 void (*set_fixmap)(unsigned idx,
      phys_addr_t phys, pgprot_t flags);
};
struct arch_spinlock;
struct pv_lock_ops {
 int (*spin_is_locked)(struct arch_spinlock *lock);
 int (*spin_is_contended)(struct arch_spinlock *lock);
 void (*spin_lock)(struct arch_spinlock *lock);
 void (*spin_lock_flags)(struct arch_spinlock *lock, unsigned long flags);
 int (*spin_trylock)(struct arch_spinlock *lock);
 void (*spin_unlock)(struct arch_spinlock *lock);
};
struct paravirt_patch_template {
 struct pv_init_ops pv_init_ops;
 struct pv_time_ops pv_time_ops;
 struct pv_cpu_ops pv_cpu_ops;
 struct pv_irq_ops pv_irq_ops;
 struct pv_apic_ops pv_apic_ops;
 struct pv_mmu_ops pv_mmu_ops;
 struct pv_lock_ops pv_lock_ops;
};
extern struct pv_info pv_info;
extern struct pv_init_ops pv_init_ops;
extern struct pv_time_ops pv_time_ops;
extern struct pv_cpu_ops pv_cpu_ops;
extern struct pv_irq_ops pv_irq_ops;
extern struct pv_apic_ops pv_apic_ops;
extern struct pv_mmu_ops pv_mmu_ops;
extern struct pv_lock_ops pv_lock_ops;
unsigned paravirt_patch_nop(void);
unsigned paravirt_patch_ident_32(void *insnbuf, unsigned len);
unsigned paravirt_patch_ident_64(void *insnbuf, unsigned len);
unsigned paravirt_patch_ignore(unsigned len);
unsigned paravirt_patch_call(void *insnbuf,
        const void *target, u16 tgt_clobbers,
        unsigned long addr, u16 site_clobbers,
        unsigned len);
unsigned paravirt_patch_jmp(void *insnbuf, const void *target,
       unsigned long addr, unsigned len);
unsigned paravirt_patch_default(u8 type, u16 clobbers, void *insnbuf,
    unsigned long addr, unsigned len);
unsigned paravirt_patch_insns(void *insnbuf, unsigned len,
         const char *start, const char *end);
unsigned native_patch(u8 type, u16 clobbers, void *ibuf,
        unsigned long addr, unsigned len);
int paravirt_disable_iospace(void);
enum paravirt_lazy_mode {
 PARAVIRT_LAZY_NONE,
 PARAVIRT_LAZY_MMU,
 PARAVIRT_LAZY_CPU,
};
enum paravirt_lazy_mode paravirt_get_lazy_mode(void);
void paravirt_start_context_switch(struct task_struct *prev);
void paravirt_end_context_switch(struct task_struct *next);
void paravirt_enter_lazy_mmu(void);
void paravirt_leave_lazy_mmu(void);
void _paravirt_nop(void);
u32 _paravirt_ident_32(u32);
u64 _paravirt_ident_64(u64);
struct paravirt_patch_site {
 u8 *instr;
 u8 instrtype;
 u8 len;
 u16 clobbers;
};
extern struct paravirt_patch_site __parainstructions[],
 __parainstructions_end[];
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef struct cpumask { unsigned long bits[(((8) + (8 * sizeof(long)) - 1) / (8 * sizeof(long)))]; } cpumask_t;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
int cpumask_next_and(int n, const struct cpumask *, const struct cpumask *);
int cpumask_any_but(const struct cpumask *mask, unsigned int cpu);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef struct cpumask cpumask_var_t[1];
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
void set_cpu_possible(unsigned int cpu, bool possible);
void set_cpu_present(unsigned int cpu, bool present);
void set_cpu_online(unsigned int cpu, bool online);
void set_cpu_active(unsigned int cpu, bool active);
void init_cpu_present(const struct cpumask *src);
void init_cpu_possible(const struct cpumask *src);
void init_cpu_online(const struct cpumask *src);
// supprimed function
// supprimed extern
// supprimed function
int __first_cpu(const cpumask_t *srcp);
int __next_cpu(int n, const cpumask_t *srcp);
int __any_online_cpu(const cpumask_t *mask);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
void arch_flush_lazy_mmu_mode(void);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
struct task_struct;
struct task_struct *__switch_to(struct task_struct *prev,
    struct task_struct *next);
struct tss_struct;
void __switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p,
        struct tss_struct *tss);
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
static unsigned long __force_order;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
void disable_hlt(void);
void enable_hlt(void);
void cpu_idle_wait(void);
// supprimed extern
// supprimed extern
void default_idle(void);
void stop_this_cpu(void *dummy);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct msr {
 union {
  struct {
   u32 l;
   u32 h;
  };
  u64 q;
 };
};
struct msr_info {
 u32 msr_no;
 struct msr reg;
 struct msr *msrs;
 int err;
};
struct msr_regs_info {
 u32 *regs;
 int err;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
struct msr *msrs_alloc(void);
void msrs_free(struct msr *msrs);
int rdmsr_on_cpu(unsigned int cpu, u32 msr_no, u32 *l, u32 *h);
int wrmsr_on_cpu(unsigned int cpu, u32 msr_no, u32 l, u32 h);
void rdmsr_on_cpus(const struct cpumask *mask, u32 msr_no, struct msr *msrs);
void wrmsr_on_cpus(const struct cpumask *mask, u32 msr_no, struct msr *msrs);
int rdmsr_safe_on_cpu(unsigned int cpu, u32 msr_no, u32 *l, u32 *h);
int wrmsr_safe_on_cpu(unsigned int cpu, u32 msr_no, u32 l, u32 h);
int rdmsr_safe_regs_on_cpu(unsigned int cpu, u32 regs[8]);
int wrmsr_safe_regs_on_cpu(unsigned int cpu, u32 regs[8]);
struct exec_domain;
struct pt_regs;
// supprimed extern
// supprimed extern
// supprimed extern
enum {
 ADDR_NO_RANDOMIZE = 0x0040000,
 FDPIC_FUNCPTRS = 0x0080000,
 MMAP_PAGE_ZERO = 0x0100000,
 ADDR_COMPAT_LAYOUT = 0x0200000,
 READ_IMPLIES_EXEC = 0x0400000,
 ADDR_LIMIT_32BIT = 0x0800000,
 SHORT_INODE = 0x1000000,
 WHOLE_SECONDS = 0x2000000,
 STICKY_TIMEOUTS = 0x4000000,
 ADDR_LIMIT_3GB = 0x8000000,
};
enum {
 PER_LINUX = 0x0000,
 PER_LINUX_32BIT = 0x0000 | ADDR_LIMIT_32BIT,
 PER_LINUX_FDPIC = 0x0000 | FDPIC_FUNCPTRS,
 PER_SVR4 = 0x0001 | STICKY_TIMEOUTS | MMAP_PAGE_ZERO,
 PER_SVR3 = 0x0002 | STICKY_TIMEOUTS | SHORT_INODE,
 PER_SCOSVR3 = 0x0003 | STICKY_TIMEOUTS |
      WHOLE_SECONDS | SHORT_INODE,
 PER_OSR5 = 0x0003 | STICKY_TIMEOUTS | WHOLE_SECONDS,
 PER_WYSEV386 = 0x0004 | STICKY_TIMEOUTS | SHORT_INODE,
 PER_ISCR4 = 0x0005 | STICKY_TIMEOUTS,
 PER_BSD = 0x0006,
 PER_SUNOS = 0x0006 | STICKY_TIMEOUTS,
 PER_XENIX = 0x0007 | STICKY_TIMEOUTS | SHORT_INODE,
 PER_LINUX32 = 0x0008,
 PER_LINUX32_3GB = 0x0008 | ADDR_LIMIT_3GB,
 PER_IRIX32 = 0x0009 | STICKY_TIMEOUTS,
 PER_IRIXN32 = 0x000a | STICKY_TIMEOUTS,
 PER_IRIX64 = 0x000b | STICKY_TIMEOUTS,
 PER_RISCOS = 0x000c,
 PER_SOLARIS = 0x000d | STICKY_TIMEOUTS,
 PER_UW7 = 0x000e | STICKY_TIMEOUTS | MMAP_PAGE_ZERO,
 PER_OSF4 = 0x000f,
 PER_HPUX = 0x0010,
 PER_MASK = 0x00ff,
};
typedef void (*handler_t)(int, struct pt_regs *);
struct exec_domain {
 const char *name;
 handler_t handler;
 unsigned char pers_low;
 unsigned char pers_high;
 unsigned long *signal_map;
 unsigned long *signal_invmap;
 struct map_segment *err_map;
 struct map_segment *socktype_map;
 struct map_segment *sockopt_map;
 struct map_segment *af_map;
 struct module *module;
 struct exec_domain *next;
};
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
u32 iter_div_u64_rem(u64 dividend, u32 divisor, u64 *remainder);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct cpuinfo_x86 {
 __u8 x86;
 __u8 x86_vendor;
 __u8 x86_model;
 __u8 x86_mask;
 char wp_works_ok;
 char hlt_works_ok;
 char hard_math;
 char rfu;
 char fdiv_bug;
 char f00f_bug;
 char coma_bug;
 char pad0;
 __u8 x86_virt_bits;
 __u8 x86_phys_bits;
 __u8 x86_coreid_bits;
 __u32 extended_cpuid_level;
 int cpuid_level;
 __u32 x86_capability[9];
 char x86_vendor_id[16];
 char x86_model_id[64];
 int x86_cache_size;
 int x86_cache_alignment;
 int x86_power;
 unsigned long loops_per_jiffy;
 cpumask_var_t llc_shared_map;
 u16 x86_max_cores;
 u16 apicid;
 u16 initial_apicid;
 u16 x86_clflush_size;
 u16 booted_cores;
 u16 phys_proc_id;
 u16 cpu_core_id;
 u16 cpu_index;
} __attribute__((__aligned__((1 << (6)))));
extern struct cpuinfo_x86 boot_cpu_data;
extern struct cpuinfo_x86 new_cpu_data;
extern struct tss_struct doublefault_tss;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
extern struct pt_regs *idle_regs(struct pt_regs *);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
struct x86_hw_tss {
 unsigned short back_link, __blh;
 unsigned long sp0;
 unsigned short ss0, __ss0h;
 unsigned long sp1;
 unsigned short ss1, __ss1h;
 unsigned long sp2;
 unsigned short ss2, __ss2h;
 unsigned long __cr3;
 unsigned long ip;
 unsigned long flags;
 unsigned long ax;
 unsigned long cx;
 unsigned long dx;
 unsigned long bx;
 unsigned long sp;
 unsigned long bp;
 unsigned long si;
 unsigned long di;
 unsigned short es, __esh;
 unsigned short cs, __csh;
 unsigned short ss, __ssh;
 unsigned short ds, __dsh;
 unsigned short fs, __fsh;
 unsigned short gs, __gsh;
 unsigned short ldt, __ldth;
 unsigned short trace;
 unsigned short io_bitmap_base;
} __attribute__((packed));
struct tss_struct {
 struct x86_hw_tss x86_tss;
 unsigned long io_bitmap[((65536/8)/sizeof(long)) + 1];
 unsigned long stack[64];
} __attribute__((__aligned__((1 << (6)))));
// supprimed extern
struct orig_ist {
 unsigned long ist[7];
};
struct i387_fsave_struct {
 u32 cwd;
 u32 swd;
 u32 twd;
 u32 fip;
 u32 fcs;
 u32 foo;
 u32 fos;
 u32 st_space[20];
 u32 status;
};
struct i387_fxsave_struct {
 u16 cwd;
 u16 swd;
 u16 twd;
 u16 fop;
 union {
  struct {
   u64 rip;
   u64 rdp;
  };
  struct {
   u32 fip;
   u32 fcs;
   u32 foo;
   u32 fos;
  };
 };
 u32 mxcsr;
 u32 mxcsr_mask;
 u32 st_space[32];
 u32 xmm_space[64];
 u32 padding[12];
 union {
  u32 padding1[12];
  u32 sw_reserved[12];
 };
} __attribute__((aligned(16)));
struct i387_soft_struct {
 u32 cwd;
 u32 swd;
 u32 twd;
 u32 fip;
 u32 fcs;
 u32 foo;
 u32 fos;
 u32 st_space[20];
 u8 ftop;
 u8 changed;
 u8 lookahead;
 u8 no_update;
 u8 rm;
 u8 alimit;
 struct math_emu_info *info;
 u32 entry_eip;
};
struct ymmh_struct {
 u32 ymmh_space[64];
};
struct xsave_hdr_struct {
 u64 xstate_bv;
 u64 reserved1[2];
 u64 reserved2[5];
} __attribute__((packed));
struct xsave_struct {
 struct i387_fxsave_struct i387;
 struct xsave_hdr_struct xsave_hdr;
 struct ymmh_struct ymmh;
} __attribute__ ((packed, aligned (64)));
union thread_xstate {
 struct i387_fsave_struct fsave;
 struct i387_fxsave_struct fxsave;
 struct i387_soft_struct soft;
 struct xsave_struct xsave;
};
struct fpu {
 union thread_xstate *state;
};
struct stack_canary {
 char __pad[20];
 unsigned long canary;
};
// supprimed extern
// supprimed extern
// supprimed extern
extern struct kmem_cache *task_xstate_cachep;
struct perf_event;
struct thread_struct {
 struct desc_struct tls_array[3];
 unsigned long sp0;
 unsigned long sp;
 unsigned long sysenter_cs;
 unsigned long ip;
 unsigned long gs;
 struct perf_event *ptrace_bps[4];
 unsigned long debugreg6;
 unsigned long ptrace_dr7;
 unsigned long cr2;
 unsigned long trap_no;
 unsigned long error_code;
 struct fpu fpu;
 struct vm86_struct *vm86_info;
 unsigned long screen_bitmap;
 unsigned long v86flags;
 unsigned long v86mask;
 unsigned long saved_sp0;
 unsigned int saved_fs;
 unsigned int saved_gs;
 unsigned long *io_bitmap_ptr;
 unsigned long iopl;
 unsigned io_bitmap_max;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
typedef struct {
 unsigned long seg;
} mm_segment_t;
// supprimed extern
// supprimed extern
// supprimed extern
unsigned long get_wchan(struct task_struct *p);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct desc_ptr early_gdt_descr;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct aperfmperf {
 u64 aperf, mperf;
};
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
struct dyn_arch_ftrace {
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef struct {
 u64 __attribute__((aligned(8))) counter;
} atomic64_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef atomic_t atomic_long_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct thread_info {
 struct task_struct *task;
 struct exec_domain *exec_domain;
 __u32 flags;
 __u32 status;
 __u32 cpu;
 int preempt_count;
 mm_segment_t addr_limit;
 struct restart_block restart_block;
 void *sysenter_return;
 unsigned long previous_esp;
 __u8 supervisor_stack[0];
 int uaccess_err;
};
register unsigned long current_stack_pointer asm("esp") __attribute__((__used__));
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct list_head {
 struct list_head *next, *prev;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct hlist_head {
 struct hlist_node *first;
};
struct hlist_node {
 struct hlist_node *next, **pprev;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct preempt_notifier;
struct preempt_ops {
 void (*sched_in)(struct preempt_notifier *notifier, int cpu);
 void (*sched_out)(struct preempt_notifier *notifier,
     struct task_struct *next);
};
struct preempt_notifier {
 struct hlist_node link;
 struct preempt_ops *ops;
};
void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
typedef struct arch_spinlock {
 unsigned int slock;
} arch_spinlock_t;
typedef struct {
 unsigned int lock;
} arch_rwlock_t;
struct task_struct;
struct lockdep_map;
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
struct lock_class_key { };
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
typedef struct raw_spinlock {
 arch_spinlock_t raw_lock;
} raw_spinlock_t;
typedef struct spinlock {
 union {
  struct raw_spinlock rlock;
 };
} spinlock_t;
typedef struct {
 arch_rwlock_t raw_lock;
} rwlock_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
int in_lock_functions(unsigned long addr);
void __attribute__((section(".spinlock.text"))) _raw_spin_lock(raw_spinlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_spin_lock_nested(raw_spinlock_t *lock, int subclass)
        ;
void __attribute__((section(".spinlock.text")))
_raw_spin_lock_nest_lock(raw_spinlock_t *lock, struct lockdep_map *map)
        ;
void __attribute__((section(".spinlock.text"))) _raw_spin_lock_bh(raw_spinlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_spin_lock_irq(raw_spinlock_t *lock)
        ;
unsigned long __attribute__((section(".spinlock.text"))) _raw_spin_lock_irqsave(raw_spinlock_t *lock)
        ;
unsigned long __attribute__((section(".spinlock.text")))
_raw_spin_lock_irqsave_nested(raw_spinlock_t *lock, int subclass)
        ;
int __attribute__((section(".spinlock.text"))) _raw_spin_trylock(raw_spinlock_t *lock);
int __attribute__((section(".spinlock.text"))) _raw_spin_trylock_bh(raw_spinlock_t *lock);
void __attribute__((section(".spinlock.text"))) _raw_spin_unlock(raw_spinlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_spin_unlock_bh(raw_spinlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_spin_unlock_irq(raw_spinlock_t *lock) ;
void __attribute__((section(".spinlock.text")))
_raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
        ;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
void __attribute__((section(".spinlock.text"))) _raw_read_lock(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_write_lock(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_read_lock_bh(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_write_lock_bh(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_read_lock_irq(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_write_lock_irq(rwlock_t *lock) ;
unsigned long __attribute__((section(".spinlock.text"))) _raw_read_lock_irqsave(rwlock_t *lock)
       ;
unsigned long __attribute__((section(".spinlock.text"))) _raw_write_lock_irqsave(rwlock_t *lock)
       ;
int __attribute__((section(".spinlock.text"))) _raw_read_trylock(rwlock_t *lock);
int __attribute__((section(".spinlock.text"))) _raw_write_trylock(rwlock_t *lock);
void __attribute__((section(".spinlock.text"))) _raw_read_unlock(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_write_unlock(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_read_unlock_bh(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_write_unlock_bh(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_read_unlock_irq(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text"))) _raw_write_unlock_irq(rwlock_t *lock) ;
void __attribute__((section(".spinlock.text")))
_raw_read_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
       ;
void __attribute__((section(".spinlock.text")))
_raw_write_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
       ;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
typedef struct {
 unsigned sequence;
 spinlock_t lock;
} seqlock_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
typedef struct seqcount {
 unsigned sequence;
} seqcount_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct timespec {
 __kernel_time_t tv_sec;
 long tv_nsec;
};
struct timeval {
 __kernel_time_t tv_sec;
 __kernel_suseconds_t tv_usec;
};
struct timezone {
 int tz_minuteswest;
 int tz_dsttime;
};
extern struct timezone sys_tz;
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
extern struct timespec timespec_add_safe(const struct timespec lhs,
      const struct timespec rhs);
// supprimed function
extern struct timespec xtime;
extern struct timespec wall_to_monotonic;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void timekeeping_init(void);
// supprimed extern
unsigned long get_seconds(void);
struct timespec current_kernel_time(void);
struct timespec __current_kernel_time(void);
struct timespec get_monotonic_coarse(void);
// supprimed function
// supprimed function
extern struct timespec ns_to_timespec(const s64 nsec);
extern struct timeval ns_to_timeval(const s64 nsec);
// supprimed function
struct itimerspec {
 struct timespec it_interval;
 struct timespec it_value;
};
struct itimerval {
 struct timeval it_interval;
 struct timeval it_value;
};
struct timex {
 unsigned int modes;
 long offset;
 long freq;
 long maxerror;
 long esterror;
 int status;
 long constant;
 long precision;
 long tolerance;
 struct timeval time;
 long tick;
 long ppsfreq;
 long jitter;
 int shift;
 long stabil;
 long jitcnt;
 long calcnt;
 long errcnt;
 long stbcnt;
 int tai;
 int :32; int :32; int :32; int :32;
 int :32; int :32; int :32; int :32;
 int :32; int :32; int :32;
};
typedef unsigned long long cycles_t;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
int read_current_timer(unsigned long *timer_val);
// supprimed extern
// supprimed extern
u64 get_jiffies_64(void);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct rb_node
{
 unsigned long rb_parent_color;
 struct rb_node *rb_right;
 struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
struct rb_root
{
 struct rb_node *rb_node;
};
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
typedef void (*rb_augment_f)(struct rb_node *node, void *data);
// supprimed extern
extern struct rb_node *rb_augment_erase_begin(struct rb_node *node);
// supprimed extern
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);
// supprimed extern
// supprimed function
typedef struct { unsigned long bits[((((1 << 0)) + (8 * sizeof(long)) - 1) / (8 * sizeof(long)))]; } nodemask_t;
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
enum node_states {
 N_POSSIBLE,
 N_ONLINE,
 N_NORMAL_MEMORY,
 N_HIGH_MEMORY,
 N_CPU,
 NR_NODE_STATES
};
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct nodemask_scratch {
 nodemask_t mask1;
 nodemask_t mask2;
};
struct raw_prio_tree_node {
 struct prio_tree_node *left;
 struct prio_tree_node *right;
 struct prio_tree_node *parent;
};
struct prio_tree_node {
 struct prio_tree_node *left;
 struct prio_tree_node *right;
 struct prio_tree_node *parent;
 unsigned long start;
 unsigned long last;
};
struct prio_tree_root {
 struct prio_tree_node *prio_tree_node;
 unsigned short index_bits;
 unsigned short raw;
};
struct prio_tree_iter {
 struct prio_tree_node *cur;
 unsigned long mask;
 unsigned long value;
 int size_level;
 struct prio_tree_root *root;
 unsigned long r_index;
 unsigned long h_index;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct prio_tree_node *prio_tree_replace(struct prio_tree_root *root,
                struct prio_tree_node *old, struct prio_tree_node *node);
struct prio_tree_node *prio_tree_insert(struct prio_tree_root *root,
                struct prio_tree_node *node);
void prio_tree_remove(struct prio_tree_root *root, struct prio_tree_node *node);
struct prio_tree_node *prio_tree_next(struct prio_tree_iter *iter);
struct rw_semaphore;
struct rwsem_waiter;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
typedef signed long rwsem_count_t;
struct rw_semaphore {
 rwsem_count_t count;
 spinlock_t wait_lock;
 struct list_head wait_list;
};
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
typedef struct __wait_queue wait_queue_t;
typedef int (*wait_queue_func_t)(wait_queue_t *wait, unsigned mode, int flags, void *key);
int default_wake_function(wait_queue_t *wait, unsigned mode, int flags, void *key);
struct __wait_queue {
 unsigned int flags;
 void *private1;
 wait_queue_func_t func;
 struct list_head task_list;
};
struct wait_bit_key {
 void *flags;
 int bit_nr;
};
struct wait_bit_queue {
 struct wait_bit_key key;
 wait_queue_t wait;
};
struct __wait_queue_head {
 spinlock_t lock;
 struct list_head task_list;
};
typedef struct __wait_queue_head wait_queue_head_t;
struct task_struct;
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key);
void __wake_up_locked_key(wait_queue_head_t *q, unsigned int mode, void *key);
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode, int nr,
   void *key);
void __wake_up_locked(wait_queue_head_t *q, unsigned int mode);
void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr);
void __wake_up_bit(wait_queue_head_t *, void *, int);
int __wait_on_bit(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned);
int __wait_on_bit_lock(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned);
void wake_up_bit(void *, int);
int out_of_line_wait_on_bit(void *, int, int (*)(void *), unsigned);
int out_of_line_wait_on_bit_lock(void *, int, int (*)(void *), unsigned);
wait_queue_head_t *bit_waitqueue(void *, int);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state);
void prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, int state);
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait);
void abort_exclusive_wait(wait_queue_head_t *q, wait_queue_t *wait,
   unsigned int mode, void *key);
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
// supprimed function
// supprimed function
struct completion {
 unsigned int done;
 wait_queue_head_t wait;
};
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
enum page_debug_flags {
 PAGE_DEBUG_FLAG_POISON,
};
struct mutex {
 atomic_t count;
 spinlock_t wait_lock;
 struct list_head wait_list;
 struct thread_info *owner;
};
struct mutex_waiter {
 struct list_head list;
 struct task_struct *task;
};
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
typedef struct {
 void *ldt;
 int size;
 struct mutex lock;
 void *vdso;
 struct desc_struct user_cs;
 unsigned long exec_limit;
} mm_context_t;
void leave_mm(int cpu);
struct address_space;
struct page {
 unsigned long flags;
 atomic_t _count;
 union {
  atomic_t _mapcount;
  struct {
   u16 inuse;
   u16 objects;
  };
 };
 union {
     struct {
  unsigned long private1;
  struct address_space *mapping;
     };
     spinlock_t ptl;
     struct kmem_cache *slab;
     struct page *first_page;
 };
 union {
  unsigned long index;
  void *freelist;
 };
 struct list_head lru;
};
struct vm_region {
 struct rb_node vm_rb;
 unsigned long vm_flags;
 unsigned long vm_start;
 unsigned long vm_end;
 unsigned long vm_top;
 unsigned long vm_pgoff;
 struct file *vm_file;
 int vm_usage;
 bool vm_icache_flushed : 1;
};
struct vm_area_struct {
 struct mm_struct * vm_mm;
 unsigned long vm_start;
 unsigned long vm_end;
 struct vm_area_struct *vm_next, *vm_prev;
 pgprot_t vm_page_prot;
 unsigned long vm_flags;
 struct rb_node vm_rb;
 union {
  struct {
   struct list_head list;
   void *parent;
   struct vm_area_struct *head;
  } vm_set;
  struct raw_prio_tree_node prio_tree_node;
 } shared;
 struct list_head anon_vma_chain;
 struct anon_vma *anon_vma;
 const struct vm_operations_struct *vm_ops;
 unsigned long vm_pgoff;
 struct file * vm_file;
 void * vm_private_data;
 unsigned long vm_truncate_count;
};
struct core_thread {
 struct task_struct *task;
 struct core_thread *next;
};
struct core_state {
 atomic_t nr_threads;
 struct core_thread dumper;
 struct completion startup;
};
enum {
 MM_FILEPAGES,
 MM_ANONPAGES,
 MM_SWAPENTS,
 NR_MM_COUNTERS
};
struct mm_rss_stat {
 atomic_long_t count[NR_MM_COUNTERS];
};
struct task_rss_stat {
 int events;
 int count[NR_MM_COUNTERS];
};
struct mm_struct {
 struct vm_area_struct * mmap;
 struct rb_root mm_rb;
 struct vm_area_struct * mmap_cache;
 unsigned long (*get_unmapped_area) (struct file *filp,
    unsigned long addr, unsigned long len,
    unsigned long pgoff, unsigned long flags);
       unsigned long (*get_unmapped_exec_area) (struct file *filp,
    unsigned long addr, unsigned long len,
    unsigned long pgoff, unsigned long flags);
 void (*unmap_area) (struct mm_struct *mm, unsigned long addr);
 unsigned long mmap_base;
 unsigned long task_size;
 unsigned long cached_hole_size;
 unsigned long free_area_cache;
 pgd_t * pgd;
 atomic_t mm_users;
 atomic_t mm_count;
 int map_count;
 struct rw_semaphore mmap_sem;
 spinlock_t page_table_lock;
 struct list_head mmlist;
 unsigned long hiwater_rss;
 unsigned long hiwater_vm;
 unsigned long total_vm, locked_vm, shared_vm, exec_vm;
 unsigned long stack_vm, reserved_vm, def_flags, nr_ptes;
 unsigned long start_code, end_code, start_data, end_data;
 unsigned long start_brk, brk, start_stack;
 unsigned long arg_start, arg_end, env_start, env_end;
 unsigned long saved_auxv[(2*(2 + 19 + 1))];
 struct mm_rss_stat rss_stat;
 struct linux_binfmt *binfmt;
 cpumask_t cpu_vm_mask;
 mm_context_t context;
 unsigned int faultstamp;
 unsigned int token_priority;
 unsigned int last_interval;
 unsigned long flags;
 struct core_state *core_state;
 spinlock_t ioctx_lock;
 struct hlist_head ioctx_list;
 struct task_struct *owner;
 struct file *exe_file;
 unsigned long num_exe_file_vmas;
 struct mmu_notifier_mm *mmu_notifier_mm;
};
typedef unsigned long cputime_t;
typedef u64 cputime64_t;
// supprimed extern
struct call_single_data {
 struct list_head list;
 void (*func) (void *info);
 void *info;
 u16 flags;
 u16 priv;
};
// supprimed extern
int smp_call_function_single(int cpuid, void (*func) (void *info), void *info,
    int wait);
struct mpf_intel {
 char signature[4];
 unsigned int physptr;
 unsigned char length;
 unsigned char specification;
 unsigned char checksum;
 unsigned char feature1;
 unsigned char feature2;
 unsigned char feature3;
 unsigned char feature4;
 unsigned char feature5;
};
struct mpc_table {
 char signature[4];
 unsigned short length;
 char spec;
 char checksum;
 char oem[8];
 char productid[12];
 unsigned int oemptr;
 unsigned short oemsize;
 unsigned short oemcount;
 unsigned int lapic;
 unsigned int reserved;
};
struct mpc_cpu {
 unsigned char type;
 unsigned char apicid;
 unsigned char apicver;
 unsigned char cpuflag;
 unsigned int cpufeature;
 unsigned int featureflag;
 unsigned int reserved[2];
};
struct mpc_bus {
 unsigned char type;
 unsigned char busid;
 unsigned char bustype[6];
};
struct mpc_ioapic {
 unsigned char type;
 unsigned char apicid;
 unsigned char apicver;
 unsigned char flags;
 unsigned int apicaddr;
};
struct mpc_intsrc {
 unsigned char type;
 unsigned char irqtype;
 unsigned short irqflag;
 unsigned char srcbus;
 unsigned char srcbusirq;
 unsigned char dstapic;
 unsigned char dstirq;
};
enum mp_irq_source_types {
 mp_INT = 0,
 mp_NMI = 1,
 mp_SMI = 2,
 mp_ExtINT = 3
};
struct mpc_lintsrc {
 unsigned char type;
 unsigned char irqtype;
 unsigned short irqflag;
 unsigned char srcbusid;
 unsigned char srcbusirq;
 unsigned char destapic;
 unsigned char destapiclint;
};
struct mpc_oemtable {
 char signature[4];
 unsigned short length;
 char rev;
 char checksum;
 char mpc[8];
};
enum mp_bustype {
 MP_BUS_ISA = 1,
 MP_BUS_EISA,
 MP_BUS_PCI,
 MP_BUS_MCA,
};
struct screen_info {
 __u8 orig_x;
 __u8 orig_y;
 __u16 ext_mem_k;
 __u16 orig_video_page;
 __u8 orig_video_mode;
 __u8 orig_video_cols;
 __u8 flags;
 __u8 unused2;
 __u16 orig_video_ega_bx;
 __u16 unused3;
 __u8 orig_video_lines;
 __u8 orig_video_isVGA;
 __u16 orig_video_points;
 __u16 lfb_width;
 __u16 lfb_height;
 __u16 lfb_depth;
 __u32 lfb_base;
 __u32 lfb_size;
 __u16 cl_magic, cl_offset;
 __u16 lfb_linelength;
 __u8 red_size;
 __u8 red_pos;
 __u8 green_size;
 __u8 green_pos;
 __u8 blue_size;
 __u8 blue_pos;
 __u8 rsvd_size;
 __u8 rsvd_pos;
 __u16 vesapm_seg;
 __u16 vesapm_off;
 __u16 pages;
 __u16 vesa_attributes;
 __u32 capabilities;
 __u8 _reserved[6];
} __attribute__((packed));
extern struct screen_info screen_info;
typedef unsigned short apm_event_t;
typedef unsigned short apm_eventinfo_t;
struct apm_bios_info {
 __u16 version;
 __u16 cseg;
 __u32 offset;
 __u16 cseg_16;
 __u16 dseg;
 __u16 flags;
 __u16 cseg_len;
 __u16 cseg_16_len;
 __u16 dseg_len;
};
struct apm_info {
 struct apm_bios_info bios;
 unsigned short connection_version;
 int get_power_status_broken;
 int get_power_status_swabinminutes;
 int allow_ints;
 int forbid_idle;
 int realmode_power_off;
 int disabled;
};
extern struct apm_info apm_info;
struct edd_device_params {
 __u16 length;
 __u16 info_flags;
 __u32 num_default_cylinders;
 __u32 num_default_heads;
 __u32 sectors_per_track;
 __u64 number_of_sectors;
 __u16 bytes_per_sector;
 __u32 dpte_ptr;
 __u16 key;
 __u8 device_path_info_length;
 __u8 reserved2;
 __u16 reserved3;
 __u8 host_bus_type[4];
 __u8 interface_type[8];
 union {
  struct {
   __u16 base_address;
   __u16 reserved1;
   __u32 reserved2;
  } __attribute__ ((packed)) isa;
  struct {
   __u8 bus;
   __u8 slot;
   __u8 function;
   __u8 channel;
   __u32 reserved;
  } __attribute__ ((packed)) pci;
  struct {
   __u64 reserved;
  } __attribute__ ((packed)) ibnd;
  struct {
   __u64 reserved;
  } __attribute__ ((packed)) xprs;
  struct {
   __u64 reserved;
  } __attribute__ ((packed)) htpt;
  struct {
   __u64 reserved;
  } __attribute__ ((packed)) unknown;
 } interface_path;
 union {
  struct {
   __u8 device;
   __u8 reserved1;
   __u16 reserved2;
   __u32 reserved3;
   __u64 reserved4;
  } __attribute__ ((packed)) ata;
  struct {
   __u8 device;
   __u8 lun;
   __u8 reserved1;
   __u8 reserved2;
   __u32 reserved3;
   __u64 reserved4;
  } __attribute__ ((packed)) atapi;
  struct {
   __u16 id;
   __u64 lun;
   __u16 reserved1;
   __u32 reserved2;
  } __attribute__ ((packed)) scsi;
  struct {
   __u64 serial_number;
   __u64 reserved;
  } __attribute__ ((packed)) usb;
  struct {
   __u64 eui;
   __u64 reserved;
  } __attribute__ ((packed)) i1394;
  struct {
   __u64 wwid;
   __u64 lun;
  } __attribute__ ((packed)) fibre;
  struct {
   __u64 identity_tag;
   __u64 reserved;
  } __attribute__ ((packed)) i2o;
  struct {
   __u32 array_number;
   __u32 reserved1;
   __u64 reserved2;
  } __attribute__ ((packed)) raid;
  struct {
   __u8 device;
   __u8 reserved1;
   __u16 reserved2;
   __u32 reserved3;
   __u64 reserved4;
  } __attribute__ ((packed)) sata;
  struct {
   __u64 reserved1;
   __u64 reserved2;
  } __attribute__ ((packed)) unknown;
 } device_path;
 __u8 reserved4;
 __u8 checksum;
} __attribute__ ((packed));
struct edd_info {
 __u8 device;
 __u8 version;
 __u16 interface_support;
 __u16 legacy_max_cylinder;
 __u8 legacy_max_head;
 __u8 legacy_sectors_per_track;
 struct edd_device_params params;
} __attribute__ ((packed));
struct edd {
 unsigned int mbr_signature[16];
 struct edd_info edd_info[6];
 unsigned char mbr_signature_nr;
 unsigned char edd_info_nr;
};
extern struct edd edd;
struct e820entry {
 __u64 addr;
 __u64 size;
 __u32 type;
} __attribute__((packed));
struct e820map {
 __u32 nr_map;
 struct e820entry map[(128 + 3 * (1 << 0))];
};
extern struct e820map e820;
extern struct e820map e820_saved;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct setup_data;
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void free_early_partial(u64 start, u64 end);
// supprimed extern
void reserve_early_without_check(u64 start, u64 end, char *name);
u64 find_early_area(u64 ei_start, u64 ei_last, u64 start, u64 end,
    u64 size, u64 align);
u64 find_early_area_size(u64 ei_start, u64 ei_last, u64 start,
    u64 *sizep, u64 align);
u64 find_fw_memmap_area(u64 start, u64 end, u64 size, u64 align);
u64 get_max_mapped(void);
struct range {
 u64 start;
 u64 end;
};
int add_range(struct range *range, int az, int nr_range,
  u64 start, u64 end);
int add_range_with_merge(struct range *range, int az, int nr_range,
    u64 start, u64 end);
void subtract_range(struct range *range, int az, u64 start, u64 end);
int clean_sort_range(struct range *range, int az);
void sort_range(struct range *range, int nr_range);
// supprimed function
int get_free_all_memory_range(struct range **rangep, int nodeid);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
struct resource {
 resource_size_t start;
 resource_size_t end;
 const char *name;
 unsigned long flags;
 struct resource *parent, *sibling, *child;
};
struct resource_list {
 struct resource_list *next;
 struct resource *res;
 struct pci_dev *dev;
};
extern struct resource ioport_resource;
extern struct resource iomem_resource;
extern struct resource *request_resource_conflict(struct resource *root, struct resource *new1);
// supprimed extern
// supprimed extern
void release_child_resources(struct resource *new1);
// supprimed extern
extern struct resource *insert_resource_conflict(struct resource *parent, struct resource *new1);
// supprimed extern
// supprimed extern
// supprimed extern
int adjust_resource(struct resource *res, resource_size_t start,
      resource_size_t size);
resource_size_t resource_alignment(struct resource *res);
// supprimed function
// supprimed function
extern struct resource * __request_region(struct resource *,
     resource_size_t start,
     resource_size_t n,
     const char *name, int flags);
// supprimed extern
// supprimed extern
// supprimed function
struct device;
extern struct resource * __devm_request_region(struct device *dev,
    struct resource *parent, resource_size_t start,
    resource_size_t n, const char *name);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct ist_info {
 __u32 signature;
 __u32 command;
 __u32 event;
 __u32 perf_level;
};
extern struct ist_info ist_info;
struct edid_info {
 unsigned char dummy[128];
};
extern struct edid_info edid_info;
struct setup_data {
 __u64 next;
 __u32 type;
 __u32 len;
 __u8 data[0];
};
struct setup_header {
 __u8 setup_sects;
 __u16 root_flags;
 __u32 syssize;
 __u16 ram_size;
 __u16 vid_mode;
 __u16 root_dev;
 __u16 boot_flag;
 __u16 jump;
 __u32 header;
 __u16 version;
 __u32 realmode_swtch;
 __u16 start_sys;
 __u16 kernel_version;
 __u8 type_of_loader;
 __u8 loadflags;
 __u16 setup_move_size;
 __u32 code32_start;
 __u32 ramdisk_image;
 __u32 ramdisk_size;
 __u32 bootsect_kludge;
 __u16 heap_end_ptr;
 __u8 ext_loader_ver;
 __u8 ext_loader_type;
 __u32 cmd_line_ptr;
 __u32 initrd_addr_max;
 __u32 kernel_alignment;
 __u8 relocatable_kernel;
 __u8 _pad2[3];
 __u32 cmdline_size;
 __u32 hardware_subarch;
 __u64 hardware_subarch_data;
 __u32 payload_offset;
 __u32 payload_length;
 __u64 setup_data;
} __attribute__((packed));
struct sys_desc_table {
 __u16 length;
 __u8 table[14];
};
struct efi_info {
 __u32 efi_loader_signature;
 __u32 efi_systab;
 __u32 efi_memdesc_size;
 __u32 efi_memdesc_version;
 __u32 efi_memmap;
 __u32 efi_memmap_size;
 __u32 efi_systab_hi;
 __u32 efi_memmap_hi;
};
struct boot_params {
 struct screen_info screen_info;
 struct apm_bios_info apm_bios_info;
 __u8 _pad2[4];
 __u64 tboot_addr;
 struct ist_info ist_info;
 __u8 _pad3[16];
 __u8 hd0_info[16];
 __u8 hd1_info[16];
 struct sys_desc_table sys_desc_table;
 __u8 _pad4[144];
 struct edid_info edid_info;
 struct efi_info efi_info;
 __u32 alt_mem_k;
 __u32 scratch;
 __u8 e820_entries;
 __u8 eddbuf_entries;
 __u8 edd_mbr_sig_buf_entries;
 __u8 _pad6[6];
 struct setup_header hdr;
 __u8 _pad7[0x290-0x1f1-sizeof(struct setup_header)];
 __u32 edd_mbr_sig_buffer[16];
 struct e820entry e820_map[128];
 __u8 _pad8[48];
 struct edd_info eddbuf[6];
 __u8 _pad9[276];
} __attribute__((packed));
enum {
 X86_SUBARCH_PC = 0,
 X86_SUBARCH_LGUEST,
 X86_SUBARCH_XEN,
 X86_SUBARCH_MRST,
 X86_NR_SUBARCHS,
};
struct mpc_bus;
struct mpc_cpu;
struct mpc_table;
struct x86_init_mpparse {
 void (*mpc_record)(unsigned int mode);
 void (*setup_ioapic_ids)(void);
 int (*mpc_apic_id)(struct mpc_cpu *m);
 void (*smp_read_mpc_oem)(struct mpc_table *mpc);
 void (*mpc_oem_pci_bus)(struct mpc_bus *m);
 void (*mpc_oem_bus_info)(struct mpc_bus *m, char *name);
 void (*find_smp_config)(void);
 void (*get_smp_config)(unsigned int early);
};
struct x86_init_resources {
 void (*probe_roms)(void);
 void (*reserve_resources)(void);
 char *(*memory_setup)(void);
};
struct x86_init_irqs {
 void (*pre_vector_init)(void);
 void (*intr_init)(void);
 void (*trap_init)(void);
};
struct x86_init_oem {
 void (*arch_setup)(void);
 void (*banner)(void);
};
struct x86_init_paging {
 void (*pagetable_setup_start)(pgd_t *base);
 void (*pagetable_setup_done)(pgd_t *base);
};
struct x86_init_timers {
 void (*setup_percpu_clockev)(void);
 void (*tsc_pre_init)(void);
 void (*timer_init)(void);
};
struct x86_init_iommu {
 int (*iommu_init)(void);
};
struct x86_init_pci {
 int (*arch_init)(void);
 int (*init)(void);
 void (*init_irq)(void);
 void (*fixup_irqs)(void);
};
struct x86_init_ops {
 struct x86_init_resources resources;
 struct x86_init_mpparse mpparse;
 struct x86_init_irqs irqs;
 struct x86_init_oem oem;
 struct x86_init_paging paging;
 struct x86_init_timers timers;
 struct x86_init_iommu iommu;
 struct x86_init_pci pci;
};
struct x86_cpuinit_ops {
 void (*setup_percpu_clockev)(void);
};
struct x86_platform_ops {
 unsigned long (*calibrate_tsc)(void);
 unsigned long (*get_wallclock)(void);
 int (*set_wallclock)(unsigned long nowtime);
 void (*iommu_shutdown)(void);
 bool (*is_untracked_pat_range)(u64 start, u64 end);
 void (*nmi_init)(void);
 int (*i8042_detect)(void);
};
extern struct x86_init_ops x86_init;
extern struct x86_cpuinit_ops x86_cpuinit;
extern struct x86_platform_ops x86_platform;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void __attribute__ ((__section__(".cpuinit.text"))) __attribute__((__cold__)) generic_processor_info(int apicid, int version);
// supprimed extern
// supprimed extern
// supprimed extern
struct device;
// supprimed extern
struct physid_mask {
 unsigned long mask[(((256) + (8 * sizeof(long)) - 1) / (8 * sizeof(long)))];
};
typedef struct physid_mask physid_mask_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void use_tsc_delay(void);
// supprimed extern
void calibrate_delay(void);
void msleep(unsigned int msecs);
unsigned long msleep_interruptible(unsigned int msecs);
// supprimed function
union ktime {
 s64 tv64;
};
typedef union ktime ktime_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
enum debug_obj_state {
 ODEBUG_STATE_NONE,
 ODEBUG_STATE_INIT,
 ODEBUG_STATE_INACTIVE,
 ODEBUG_STATE_ACTIVE,
 ODEBUG_STATE_DESTROYED,
 ODEBUG_STATE_NOTAVAILABLE,
 ODEBUG_STATE_MAX,
};
struct debug_obj_descr;
struct debug_obj {
 struct hlist_node node;
 enum debug_obj_state state;
 unsigned int astate;
 void *object;
 struct debug_obj_descr *descr;
};
struct debug_obj_descr {
 const char *name;
 int (*fixup_init) (void *addr, enum debug_obj_state state);
 int (*fixup_activate) (void *addr, enum debug_obj_state state);
 int (*fixup_destroy) (void *addr, enum debug_obj_state state);
 int (*fixup_free) (void *addr, enum debug_obj_state state);
};
static inline void
debug_object_init (void *addr, struct debug_obj_descr *descr) { }
// supprimed function
static inline void
debug_object_activate (void *addr, struct debug_obj_descr *descr) { }
// supprimed function
static inline void
debug_object_destroy (void *addr, struct debug_obj_descr *descr) { }
static inline void
debug_object_free (void *addr, struct debug_obj_descr *descr) { }
// supprimed function
// supprimed function
// supprimed function
struct tvec_base;
struct timer_list {
 struct list_head entry;
 unsigned long expires;
 struct tvec_base *base;
 void (*function)(unsigned long);
 unsigned long data;
 int slack;
 void *start_site;
 char start_comm[16];
 int start_pid;
};
extern struct tvec_base boot_tvec_bases;
void init_timer_key(struct timer_list *timer,
      const char *name,
      struct lock_class_key *key);
void init_timer_deferrable_key(struct timer_list *timer,
          const char *name,
          struct lock_class_key *key);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
  extern int try_to_del_timer_sync(struct timer_list *timer);
  extern int del_timer_sync(struct timer_list *timer);
// supprimed extern
// supprimed extern
struct hrtimer;
extern enum hrtimer_restart it_real_fn(struct hrtimer *);
unsigned long __round_jiffies(unsigned long j, int cpu);
unsigned long __round_jiffies_relative(unsigned long j, int cpu);
unsigned long round_jiffies(unsigned long j);
unsigned long round_jiffies_relative(unsigned long j);
unsigned long __round_jiffies_up(unsigned long j, int cpu);
unsigned long __round_jiffies_up_relative(unsigned long j, int cpu);
unsigned long round_jiffies_up(unsigned long j);
unsigned long round_jiffies_up_relative(unsigned long j);
struct workqueue_struct;
struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
struct work_struct {
 atomic_long_t data;
 struct list_head entry;
 work_func_t func;
};
struct delayed_work {
 struct work_struct work;
 struct timer_list timer;
};
// supprimed function
struct execute_work {
 struct work_struct work;
};
// supprimed function
// supprimed function
extern struct workqueue_struct *
__create_workqueue_key(const char *name, int singlethread,
         int freezeable, int rt, struct lock_class_key *key,
         const char *lock_name);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
int execute_in_process_context(work_func_t fn, struct execute_work *);
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
long work_on_cpu(unsigned int cpu, long (*fn)(void *), void *arg);
// supprimed extern
// supprimed extern
// supprimed extern
struct device;
typedef struct pm_message {
 int event;
} pm_message_t;
struct dev_pm_ops {
 int (*prepare)(struct device *dev);
 void (*complete)(struct device *dev);
 int (*suspend)(struct device *dev);
 int (*resume)(struct device *dev);
 int (*freeze)(struct device *dev);
 int (*thaw)(struct device *dev);
 int (*poweroff)(struct device *dev);
 int (*restore)(struct device *dev);
 int (*suspend_noirq)(struct device *dev);
 int (*resume_noirq)(struct device *dev);
 int (*freeze_noirq)(struct device *dev);
 int (*thaw_noirq)(struct device *dev);
 int (*poweroff_noirq)(struct device *dev);
 int (*restore_noirq)(struct device *dev);
 int (*runtime_suspend)(struct device *dev);
 int (*runtime_resume)(struct device *dev);
 int (*runtime_idle)(struct device *dev);
};
extern struct dev_pm_ops generic_subsys_pm_ops;
enum dpm_state {
 DPM_INVALID,
 DPM_ON,
 DPM_PREPARING,
 DPM_RESUMING,
 DPM_SUSPENDING,
 DPM_OFF,
 DPM_OFF_IRQ,
};
enum rpm_status {
 RPM_ACTIVE = 0,
 RPM_RESUMING,
 RPM_SUSPENDED,
 RPM_SUSPENDING,
};
enum rpm_request {
 RPM_REQ_NONE = 0,
 RPM_REQ_IDLE,
 RPM_REQ_SUSPEND,
 RPM_REQ_RESUME,
};
struct dev_pm_info {
 pm_message_t power_state;
 unsigned int can_wakeup:1;
 unsigned int should_wakeup:1;
 unsigned async_suspend:1;
 enum dpm_state status;
 struct list_head entry;
 struct completion completion;
 struct timer_list suspend_timer;
 unsigned long timer_expires;
 struct work_struct work;
 wait_queue_head_t wait_queue;
 spinlock_t lock;
 atomic_t usage_count;
 atomic_t child_count;
 unsigned int disable_depth:3;
 unsigned int ignore_children:1;
 unsigned int idle_notification:1;
 unsigned int request_pending:1;
 unsigned int deferred_resume:1;
 unsigned int run_wake:1;
 unsigned int runtime_auto:1;
 enum rpm_request request;
 enum rpm_status runtime_status;
 int runtime_error;
 unsigned long active_jiffies;
 unsigned long suspended_jiffies;
 unsigned long accounting_timestamp;
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
enum dpm_order {
 DPM_ORDER_NONE,
 DPM_ORDER_DEV_AFTER_PARENT,
 DPM_ORDER_PARENT_BEFORE_DEV,
 DPM_ORDER_DEV_LAST,
};
// supprimed extern
struct local_apic {
        struct { unsigned int __reserved[4]; } __reserved_01;
        struct { unsigned int __reserved[4]; } __reserved_02;
        struct {
  unsigned int __reserved_1 : 24,
   phys_apic_id : 4,
   __reserved_2 : 4;
  unsigned int __reserved[3];
 } id;
        const
 struct {
  unsigned int version : 8,
   __reserved_1 : 8,
   max_lvt : 8,
   __reserved_2 : 8;
  unsigned int __reserved[3];
 } version;
        struct { unsigned int __reserved[4]; } __reserved_03;
        struct { unsigned int __reserved[4]; } __reserved_04;
        struct { unsigned int __reserved[4]; } __reserved_05;
        struct { unsigned int __reserved[4]; } __reserved_06;
        struct {
  unsigned int priority : 8,
   __reserved_1 : 24;
  unsigned int __reserved_2[3];
 } tpr;
        const
 struct {
  unsigned int priority : 8,
   __reserved_1 : 24;
  unsigned int __reserved_2[3];
 } apr;
        const
 struct {
  unsigned int priority : 8,
   __reserved_1 : 24;
  unsigned int __reserved_2[3];
 } ppr;
        struct {
  unsigned int eoi;
  unsigned int __reserved[3];
 } eoi;
        struct { unsigned int __reserved[4]; } __reserved_07;
        struct {
  unsigned int __reserved_1 : 24,
   logical_dest : 8;
  unsigned int __reserved_2[3];
 } ldr;
        struct {
  unsigned int __reserved_1 : 28,
   model : 4;
  unsigned int __reserved_2[3];
 } dfr;
        struct {
  unsigned int spurious_vector : 8,
   apic_enabled : 1,
   focus_cpu : 1,
   __reserved_2 : 22;
  unsigned int __reserved_3[3];
 } svr;
        struct {
         unsigned int bitfield;
  unsigned int __reserved[3];
 } isr [8];
        struct {
         unsigned int bitfield;
  unsigned int __reserved[3];
 } tmr [8];
        struct {
         unsigned int bitfield;
  unsigned int __reserved[3];
 } irr [8];
        union {
  struct {
   unsigned int send_cs_error : 1,
    receive_cs_error : 1,
    send_accept_error : 1,
    receive_accept_error : 1,
    __reserved_1 : 1,
    send_illegal_vector : 1,
    receive_illegal_vector : 1,
    illegal_register_address : 1,
    __reserved_2 : 24;
   unsigned int __reserved_3[3];
  } error_bits;
  struct {
   unsigned int errors;
   unsigned int __reserved_3[3];
  } all_errors;
 } esr;
        struct { unsigned int __reserved[4]; } __reserved_08;
        struct { unsigned int __reserved[4]; } __reserved_09;
        struct { unsigned int __reserved[4]; } __reserved_10;
        struct { unsigned int __reserved[4]; } __reserved_11;
        struct { unsigned int __reserved[4]; } __reserved_12;
        struct { unsigned int __reserved[4]; } __reserved_13;
        struct { unsigned int __reserved[4]; } __reserved_14;
        struct {
  unsigned int vector : 8,
   delivery_mode : 3,
   destination_mode : 1,
   delivery_status : 1,
   __reserved_1 : 1,
   level : 1,
   trigger : 1,
   __reserved_2 : 2,
   shorthand : 2,
   __reserved_3 : 12;
  unsigned int __reserved_4[3];
 } icr1;
        struct {
  union {
   unsigned int __reserved_1 : 24,
    phys_dest : 4,
    __reserved_2 : 4;
   unsigned int __reserved_3 : 24,
    logical_dest : 8;
  } dest;
  unsigned int __reserved_4[3];
 } icr2;
        struct {
  unsigned int vector : 8,
   __reserved_1 : 4,
   delivery_status : 1,
   __reserved_2 : 3,
   mask : 1,
   timer_mode : 1,
   __reserved_3 : 14;
  unsigned int __reserved_4[3];
 } lvt_timer;
        struct {
  unsigned int vector : 8,
   delivery_mode : 3,
   __reserved_1 : 1,
   delivery_status : 1,
   __reserved_2 : 3,
   mask : 1,
   __reserved_3 : 15;
  unsigned int __reserved_4[3];
 } lvt_thermal;
        struct {
  unsigned int vector : 8,
   delivery_mode : 3,
   __reserved_1 : 1,
   delivery_status : 1,
   __reserved_2 : 3,
   mask : 1,
   __reserved_3 : 15;
  unsigned int __reserved_4[3];
 } lvt_pc;
        struct {
  unsigned int vector : 8,
   delivery_mode : 3,
   __reserved_1 : 1,
   delivery_status : 1,
   polarity : 1,
   remote_irr : 1,
   trigger : 1,
   mask : 1,
   __reserved_2 : 15;
  unsigned int __reserved_3[3];
 } lvt_lint0;
        struct {
  unsigned int vector : 8,
   delivery_mode : 3,
   __reserved_1 : 1,
   delivery_status : 1,
   polarity : 1,
   remote_irr : 1,
   trigger : 1,
   mask : 1,
   __reserved_2 : 15;
  unsigned int __reserved_3[3];
 } lvt_lint1;
        struct {
  unsigned int vector : 8,
   __reserved_1 : 4,
   delivery_status : 1,
   __reserved_2 : 3,
   mask : 1,
   __reserved_3 : 15;
  unsigned int __reserved_4[3];
 } lvt_error;
        struct {
  unsigned int initial_count;
  unsigned int __reserved_2[3];
 } timer_icr;
        const
 struct {
  unsigned int curr_count;
  unsigned int __reserved_2[3];
 } timer_ccr;
        struct { unsigned int __reserved[4]; } __reserved_16;
        struct { unsigned int __reserved[4]; } __reserved_17;
        struct { unsigned int __reserved[4]; } __reserved_18;
        struct { unsigned int __reserved[4]; } __reserved_19;
        struct {
  unsigned int divisor : 4,
   __reserved_1 : 28;
  unsigned int __reserved_2[3];
 } timer_dcr;
        struct { unsigned int __reserved[4]; } __reserved_20;
} __attribute__ ((packed));
// supprimed extern
// supprimed extern
// supprimed extern
int __acpi_acquire_global_lock(unsigned int *lock);
int __acpi_release_global_lock(unsigned int *lock);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void acpi_pic_sci_set_trigger(unsigned int, u16);
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
struct bootnode;
// supprimed function
// supprimed extern
enum fixed_addresses {
 FIX_HOLE,
 FIX_VDSO,
 FIX_DBGP_BASE,
 FIX_EARLYCON_MEM_BASE,
 FIX_APIC_BASE,
 FIX_IO_APIC_BASE_0,
 FIX_IO_APIC_BASE_END = FIX_IO_APIC_BASE_0 + 64 - 1,
 FIX_KMAP_BEGIN,
 FIX_KMAP_END = FIX_KMAP_BEGIN+(KM_TYPE_NR*8)-1,
 FIX_PCIE_MCFG,
 FIX_PARAVIRT_BOOTMAP,
 FIX_TEXT_POKE1,
 FIX_TEXT_POKE0,
 __end_of_permanent_fixed_addresses,
 FIX_BTMAP_END =
  (__end_of_permanent_fixed_addresses ^
   (__end_of_permanent_fixed_addresses + (64 * 4) - 1)) &
  -512
  ? __end_of_permanent_fixed_addresses + (64 * 4) -
    (__end_of_permanent_fixed_addresses & ((64 * 4) - 1))
  : __end_of_permanent_fixed_addresses,
 FIX_BTMAP_BEGIN = FIX_BTMAP_END + (64 * 4) - 1,
 FIX_WP_TEST,
 __end_of_fixed_addresses
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void __native_set_fixmap(enum fixed_addresses idx, pte_t pte);
void native_set_fixmap(enum fixed_addresses idx,
         phys_addr_t phys, pgprot_t flags);
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
struct apic {
 char *name;
 int (*probe)(void);
 int (*acpi_madt_oem_check)(char *oem_id, char *oem_table_id);
 int (*apic_id_registered)(void);
 u32 irq_delivery_mode;
 u32 irq_dest_mode;
 const struct cpumask *(*target_cpus)(void);
 int disable_esr;
 int dest_logical;
 unsigned long (*check_apicid_used)(physid_mask_t *map, int apicid);
 unsigned long (*check_apicid_present)(int apicid);
 void (*vector_allocation_domain)(int cpu, struct cpumask *retmask);
 void (*init_apic_ldr)(void);
 void (*ioapic_phys_id_map)(physid_mask_t *phys_map, physid_mask_t *retmap);
 void (*setup_apic_routing)(void);
 int (*multi_timer_check)(int apic, int irq);
 int (*apicid_to_node)(int logical_apicid);
 int (*cpu_to_logical_apicid)(int cpu);
 int (*cpu_present_to_apicid)(int mps_cpu);
 void (*apicid_to_cpu_present)(int phys_apicid, physid_mask_t *retmap);
 void (*setup_portio_remap)(void);
 int (*check_phys_apicid_present)(int phys_apicid);
 void (*enable_apic_mode)(void);
 int (*phys_pkg_id)(int cpuid_apic, int index_msb);
 int (*mps_oem_check)(struct mpc_table *mpc, char *oem, char *productid);
 unsigned int (*get_apic_id)(unsigned long x);
 unsigned long (*set_apic_id)(unsigned int id);
 unsigned long apic_id_mask;
 unsigned int (*cpu_mask_to_apicid)(const struct cpumask *cpumask);
 unsigned int (*cpu_mask_to_apicid_and)(const struct cpumask *cpumask,
            const struct cpumask *andmask);
 void (*send_IPI_mask)(const struct cpumask *mask, int vector);
 void (*send_IPI_mask_allbutself)(const struct cpumask *mask,
      int vector);
 void (*send_IPI_allbutself)(int vector);
 void (*send_IPI_all)(int vector);
 void (*send_IPI_self)(int vector);
 int (*wakeup_secondary_cpu)(int apicid, unsigned long start_eip);
 int trampoline_phys_low;
 int trampoline_phys_high;
 void (*wait_for_init_deassert)(atomic_t *deassert);
 void (*smp_callin_clear_local_apic)(void);
 void (*inquire_remote_apic)(int apicid);
 u32 (*read)(u32 reg);
 void (*write)(u32 reg, u32 v);
 u64 (*icr_read)(void);
 void (*icr_write)(u32 low, u32 high);
 void (*wait_icr_idle)(void);
 u32 (*safe_wait_icr_idle)(void);
};
extern struct apic *apic;
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
extern struct apic apic_noop;
extern struct apic apic_default;
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
union IO_APIC_reg_00 {
 u32 raw;
 struct {
  u32 __reserved_2 : 14,
   LTS : 1,
   delivery_type : 1,
   __reserved_1 : 8,
   ID : 8;
 } __attribute__ ((packed)) bits;
};
union IO_APIC_reg_01 {
 u32 raw;
 struct {
  u32 version : 8,
   __reserved_2 : 7,
   PRQ : 1,
   entries : 8,
   __reserved_1 : 8;
 } __attribute__ ((packed)) bits;
};
union IO_APIC_reg_02 {
 u32 raw;
 struct {
  u32 __reserved_2 : 24,
   arbitration : 4,
   __reserved_1 : 4;
 } __attribute__ ((packed)) bits;
};
union IO_APIC_reg_03 {
 u32 raw;
 struct {
  u32 boot_DT : 1,
   __reserved_1 : 31;
 } __attribute__ ((packed)) bits;
};
enum ioapic_irq_destination_types {
 dest_Fixed = 0,
 dest_LowestPrio = 1,
 dest_SMI = 2,
 dest__reserved_1 = 3,
 dest_NMI = 4,
 dest_INIT = 5,
 dest__reserved_2 = 6,
 dest_ExtINT = 7
};
struct IO_APIC_route_entry {
 __u32 vector : 8,
  delivery_mode : 3,
  dest_mode : 1,
  delivery_status : 1,
  polarity : 1,
  irr : 1,
  trigger : 1,
  mask : 1,
  __reserved_2 : 15;
 __u32 __reserved_3 : 24,
  dest : 8;
} __attribute__ ((packed));
struct IR_IO_APIC_route_entry {
 __u64 vector : 8,
  zero : 3,
  index2 : 1,
  delivery_status : 1,
  polarity : 1,
  irr : 1,
  trigger : 1,
  mask : 1,
  reserved : 31,
  format : 1,
  index : 15;
} __attribute__ ((packed));
// supprimed extern
// supprimed extern
extern struct mpc_ioapic mp_ioapics[64];
// supprimed extern
extern struct mpc_intsrc mp_irqs[256];
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct io_apic_irq_attr;
// supprimed extern
void setup_IO_APIC_irq_extra(u32 gsi);
// supprimed extern
// supprimed extern
extern struct IO_APIC_route_entry **alloc_ioapic_entries(void);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct mp_ioapic_gsi{
 u32 gsi_base;
 u32 gsi_end;
};
extern struct mp_ioapic_gsi mp_gsi_routing[];
// supprimed extern
int mp_find_ioapic(u32 gsi);
int mp_find_ioapic_pin(int ioapic, u32 gsi);
void __attribute__ ((__section__(".init.text"))) __attribute__((__cold__)) __attribute__((no_instrument_function)) mp_register_ioapic(int id, u32 address, u32 gsi_base);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
extern struct {
 void *sp;
 unsigned short ss;
} stack_start;
struct smp_ops {
 void (*smp_prepare_boot_cpu)(void);
 void (*smp_prepare_cpus)(unsigned max_cpus);
 void (*smp_cpus_done)(unsigned max_cpus);
 void (*stop_other_cpus)(int wait);
 void (*smp_send_reschedule)(int cpu);
 int (*cpu_up)(unsigned cpu);
 int (*cpu_disable)(void);
 void (*cpu_die)(unsigned int cpu);
 void (*play_dead)(void);
 void (*send_call_func_ipi)(const struct cpumask *mask);
 void (*send_call_func_single_ipi)(int cpu);
};
// supprimed extern
extern struct smp_ops smp_ops;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
void cpu_disable_common(void);
void native_smp_prepare_boot_cpu(void);
void native_smp_prepare_cpus(unsigned int max_cpus);
void native_smp_cpus_done(unsigned int max_cpus);
int native_cpu_up(unsigned int cpunum);
int native_cpu_disable(void);
void native_cpu_die(unsigned int cpu);
void native_play_dead(void);
void play_dead_common(void);
void wbinvd_on_cpu(int cpu);
int wbinvd_on_all_cpus(void);
void native_send_call_func_ipi(const struct cpumask *mask);
void native_send_call_func_single_ipi(int cpu);
void smp_store_cpu_info(int id);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
int smp_call_function(void(*func)(void *info), void *info, int wait);
void smp_call_function_many(const struct cpumask *mask,
       void (*func)(void *info), void *info, bool wait);
void __smp_call_function_single(int cpuid, struct call_single_data *data,
    int wait);
int smp_call_function_any(const struct cpumask *mask,
     void (*func)(void *info), void *info, int wait);
void generic_smp_call_function_single_interrupt(void);
void generic_smp_call_function_interrupt(void);
void ipi_call_lock(void);
void ipi_call_unlock(void);
void ipi_call_lock_irq(void);
void ipi_call_unlock_irq(void);
int on_each_cpu(void (*func) (void *info), void *info, int wait);
void smp_prepare_boot_cpu(void);
// supprimed extern
// supprimed extern
void smp_setup_processor_id(void);
struct ipc_perm
{
 __kernel_key_t key;
 __kernel_uid_t uid;
 __kernel_gid_t gid;
 __kernel_uid_t cuid;
 __kernel_gid_t cgid;
 __kernel_mode_t mode;
 unsigned short seq;
};
struct ipc64_perm {
 __kernel_key_t key;
 __kernel_uid32_t uid;
 __kernel_gid32_t gid;
 __kernel_uid32_t cuid;
 __kernel_gid32_t cgid;
 __kernel_mode_t mode;
 unsigned char __pad1[4 - sizeof(__kernel_mode_t)];
 unsigned short seq;
 unsigned short __pad2;
 unsigned long __unused1;
 unsigned long __unused2;
};
struct ipc_kludge {
 struct msgbuf *msgp;
 long msgtyp;
};
struct kern_ipc_perm
{
 spinlock_t lock;
 int deleted;
 int id;
 key_t key;
 uid_t uid;
 gid_t gid;
 uid_t cuid;
 gid_t cgid;
 mode_t mode;
 unsigned long seq;
 void *security;
};
struct semid_ds {
 struct ipc_perm sem_perm;
 __kernel_time_t sem_otime;
 __kernel_time_t sem_ctime;
 struct sem *sem_base;
 struct sem_queue *sem_pending;
 struct sem_queue **sem_pending_last;
 struct sem_undo *undo;
 unsigned short sem_nsems;
};
struct semid64_ds {
 struct ipc64_perm sem_perm;
 __kernel_time_t sem_otime;
 unsigned long __unused1;
 __kernel_time_t sem_ctime;
 unsigned long __unused2;
 unsigned long sem_nsems;
 unsigned long __unused3;
 unsigned long __unused4;
};
struct sembuf {
 unsigned short sem_num;
 short sem_op;
 short sem_flg;
};
union semun {
 int val;
 struct semid_ds *buf;
 unsigned short *array;
 struct seminfo *__buf;
 void *__pad;
};
struct seminfo {
 int semmap;
 int semmni;
 int semmns;
 int semmnu;
 int semmsl;
 int semopm;
 int semume;
 int semusz;
 int semvmx;
 int semaem;
};
struct rcu_head {
 struct rcu_head *next;
 void (*func)(struct rcu_head *head);
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct notifier_block;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
void rcu_enter_nohz(void);
void rcu_exit_nohz(void);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct rcu_synchronize {
 struct rcu_head head;
 struct completion completion;
};
// supprimed extern
// supprimed extern
// supprimed extern
struct task_struct;
struct sem {
 int semval;
 int sempid;
 struct list_head sem_pending;
};
struct sem_array {
 struct kern_ipc_perm __attribute__((__aligned__((1 << (6)))))
    sem_perm;
 time_t sem_otime;
 time_t sem_ctime;
 struct sem *sem_base;
 struct list_head sem_pending;
 struct list_head list_id;
 int sem_nsems;
 int complex_count;
};
struct sem_queue {
 struct list_head simple_list;
 struct list_head list;
 struct task_struct *sleeper;
 struct sem_undo *undo;
 int pid;
 int status;
 struct sembuf *sops;
 int nsops;
 int alter;
};
struct sem_undo {
 struct list_head list_proc;
 struct rcu_head rcu;
 struct sem_undo_list *ulp;
 struct list_head list_id;
 int semid;
 short * semadj;
};
struct sem_undo_list {
 atomic_t refcnt;
 spinlock_t lock;
 struct list_head list_proc;
};
struct sysv_sem {
 struct sem_undo_list *undo_list;
};
// supprimed extern
// supprimed extern
struct siginfo;
typedef unsigned long old_sigset_t;
typedef struct {
 unsigned long sig[(64 / 32)];
} sigset_t;
typedef void __signalfn_t(int);
typedef __signalfn_t *__sighandler_t;
typedef void __restorefn_t(void);
typedef __restorefn_t *__sigrestore_t;
// supprimed extern
struct old_sigaction {
 __sighandler_t sa_handler;
 old_sigset_t sa_mask;
 unsigned long sa_flags;
 __sigrestore_t sa_restorer;
};
struct sigaction {
 __sighandler_t sa_handler;
 unsigned long sa_flags;
 __sigrestore_t sa_restorer;
 sigset_t sa_mask;
};
struct k_sigaction {
 struct sigaction sa;
};
typedef struct sigaltstack {
 void *ss_sp;
 int ss_flags;
 size_t ss_size;
} stack_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct pt_regs;
typedef union sigval {
 int sival_int;
 void *sival_ptr;
} sigval_t;
typedef struct siginfo {
 int si_signo;
 int si_errno;
 int si_code;
 union {
  int _pad[((128 - (3 * sizeof(int))) / sizeof(int))];
  struct {
   __kernel_pid_t _pid;
   __kernel_uid32_t _uid;
  } _kill;
  struct {
   __kernel_timer_t _tid;
   int _overrun;
   char _pad[sizeof( __kernel_uid32_t) - sizeof(int)];
   sigval_t _sigval;
   int _sys_private;
  } _timer;
  struct {
   __kernel_pid_t _pid;
   __kernel_uid32_t _uid;
   sigval_t _sigval;
  } _rt;
  struct {
   __kernel_pid_t _pid;
   __kernel_uid32_t _uid;
   int _status;
   __kernel_clock_t _utime;
   __kernel_clock_t _stime;
  } _sigchld;
  struct {
   void *_addr;
   short _addr_lsb;
  } _sigfault;
  struct {
   long _band;
   int _fd;
  } _sigpoll;
 } _sifields;
} siginfo_t;
typedef struct sigevent {
 sigval_t sigev_value;
 int sigev_signo;
 int sigev_notify;
 union {
  int _pad[((64 - (sizeof(int) * 2 + sizeof(sigval_t))) / sizeof(int))];
   int _tid;
  struct {
   void (*_function)(sigval_t);
   void *_attribute;
  } _sigev_thread;
 } _sigev_un;
} sigevent_t;
struct siginfo;
void do_schedule_next_timer(struct siginfo *info);
// supprimed function
// supprimed extern
// supprimed extern
struct sigqueue {
 struct list_head list;
 int flags;
 siginfo_t info;
 struct user_struct *user;
};
struct sigpending {
 struct list_head list;
 sigset_t signal;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct pt_regs;
// supprimed extern
// supprimed extern
extern struct kmem_cache *sighand_cachep;
int unhandled_signal(struct task_struct *tsk, int sig);
void signals_init(void);
struct dentry;
struct vfsmount;
struct path {
 struct vfsmount *mnt;
 struct dentry *dentry;
};
// supprimed extern
// supprimed extern
enum pid_type
{
 PIDTYPE_PID,
 PIDTYPE_PGID,
 PIDTYPE_SID,
 PIDTYPE_MAX
};
struct upid {
 int nr;
 struct pid_namespace *ns;
 struct hlist_node pid_chain;
};
struct pid
{
 atomic_t count;
 unsigned int level;
 struct hlist_head tasks[PIDTYPE_MAX];
 struct rcu_head rcu;
 struct upid numbers[1];
};
extern struct pid init_struct_pid;
struct pid_link
{
 struct hlist_node node;
 struct pid *pid;
};
// supprimed function
// supprimed extern
extern struct task_struct *pid_task(struct pid *pid, enum pid_type);
extern struct task_struct *get_pid_task(struct pid *pid, enum pid_type);
extern struct pid *get_task_pid(struct task_struct *task, enum pid_type type);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct pid_namespace;
extern struct pid_namespace init_pid_ns;
extern struct pid *find_pid_ns(int nr, struct pid_namespace *ns);
extern struct pid *find_vpid(int nr);
extern struct pid *find_get_pid(int nr);
extern struct pid *find_ge_pid(int nr, struct pid_namespace *);
int next_pidmap(struct pid_namespace *pid_ns, int last);
extern struct pid *alloc_pid(struct pid_namespace *ns);
// supprimed extern
// supprimed function
// supprimed function
pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns);
pid_t pid_vnr(struct pid *pid);
// supprimed extern
// supprimed extern
struct pcpu_group_info {
 int nr_units;
 unsigned long base_offset;
 unsigned int *cpu_map;
};
struct pcpu_alloc_info {
 size_t static_size;
 size_t reserved_size;
 size_t dyn_size;
 size_t unit_size;
 size_t atom_size;
 size_t alloc_size;
 size_t __ai_size;
 int nr_groups;
 struct pcpu_group_info groups[];
};
enum pcpu_fc {
 PCPU_FC_AUTO,
 PCPU_FC_EMBED,
 PCPU_FC_PAGE,
 PCPU_FC_NR,
};
// supprimed extern
extern enum pcpu_fc pcpu_chosen_fc;
typedef void * (*pcpu_fc_alloc_fn_t)(unsigned int cpu, size_t size,
         size_t align);
typedef void (*pcpu_fc_free_fn_t)(void *ptr, size_t size);
typedef void (*pcpu_fc_populate_pte_fn_t)(unsigned long addr);
typedef int (pcpu_fc_cpu_distance_fn_t)(unsigned int from, unsigned int to);
extern struct pcpu_alloc_info * __attribute__ ((__section__(".init.text"))) __attribute__((__cold__)) __attribute__((no_instrument_function)) pcpu_alloc_alloc_info(int nr_groups,
            int nr_units);
// supprimed extern
extern struct pcpu_alloc_info * __attribute__ ((__section__(".init.text"))) __attribute__((__cold__)) __attribute__((no_instrument_function)) pcpu_build_alloc_info(
    size_t reserved_size, ssize_t dyn_size,
    size_t atom_size,
    pcpu_fc_cpu_distance_fn_t cpu_distance_fn);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
enum pageblock_bits {
 PB_migrate,
 PB_migrate_end = PB_migrate + 3 - 1,
 NR_PAGEBLOCK_BITS
};
struct page;
unsigned long get_pageblock_flags_group(struct page *page,
     int start_bitidx, int end_bitidx);
void set_pageblock_flags_group(struct page *page, unsigned long flags,
     int start_bitidx, int end_bitidx);
// supprimed extern
// supprimed function
struct free_area {
 struct list_head free_list[5];
 unsigned long nr_free;
};
struct pglist_data;
struct zone_padding {
 char x[0];
} __attribute__((__aligned__(1 << (6))));
enum zone_stat_item {
 NR_FREE_PAGES,
 NR_LRU_BASE,
 NR_INACTIVE_ANON = NR_LRU_BASE,
 NR_ACTIVE_ANON,
 NR_INACTIVE_FILE,
 NR_ACTIVE_FILE,
 NR_UNEVICTABLE,
 NR_MLOCK,
 NR_ANON_PAGES,
 NR_FILE_MAPPED,
 NR_FILE_PAGES,
 NR_FILE_DIRTY,
 NR_WRITEBACK,
 NR_SLAB_RECLAIMABLE,
 NR_SLAB_UNRECLAIMABLE,
 NR_PAGETABLE,
 NR_KERNEL_STACK,
 NR_UNSTABLE_NFS,
 NR_BOUNCE,
 NR_VMSCAN_WRITE,
 NR_WRITEBACK_TEMP,
 NR_ISOLATED_ANON,
 NR_ISOLATED_FILE,
 NR_SHMEM,
 NR_VM_ZONE_STAT_ITEMS };
enum lru_list {
 LRU_INACTIVE_ANON = 0,
 LRU_ACTIVE_ANON = 0 + 1,
 LRU_INACTIVE_FILE = 0 + 2,
 LRU_ACTIVE_FILE = 0 + 2 + 1,
 LRU_UNEVICTABLE,
 NR_LRU_LISTS
};
// supprimed function
// supprimed function
// supprimed function
enum zone_watermarks {
 WMARK_MIN,
 WMARK_LOW,
 WMARK_HIGH,
 NR_WMARK
};
struct per_cpu_pages {
 int count;
 int high;
 int batch;
 struct list_head lists[3];
};
struct per_cpu_pageset {
 struct per_cpu_pages pcp;
 s8 stat_threshold;
 s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
};
enum zone_type {
 ZONE_DMA,
 ZONE_NORMAL,
 ZONE_HIGHMEM,
 ZONE_MOVABLE,
 __MAX_NR_ZONES
};
struct zone_reclaim_stat {
 unsigned long recent_rotated[2];
 unsigned long recent_scanned[2];
 unsigned long nr_saved_scan[NR_LRU_LISTS];
};
struct zone {
 unsigned long watermark[NR_WMARK];
 unsigned long percpu_drift_mark;
 unsigned long lowmem_reserve[4];
 struct per_cpu_pageset *pageset;
 spinlock_t lock;
 int all_unreclaimable;
 struct free_area free_area[11];
 unsigned long *pageblock_flags;
 struct zone_padding _pad1_;
 spinlock_t lru_lock;
 struct zone_lru {
  struct list_head list;
 } lru[NR_LRU_LISTS];
 struct zone_reclaim_stat reclaim_stat;
 unsigned long pages_scanned;
 unsigned long flags;
 atomic_long_t vm_stat[NR_VM_ZONE_STAT_ITEMS];
 int prev_priority;
 unsigned int inactive_ratio;
 struct zone_padding _pad2_;
 wait_queue_head_t * wait_table;
 unsigned long wait_table_hash_nr_entries;
 unsigned long wait_table_bits;
 struct pglist_data *zone_pgdat;
 unsigned long zone_start_pfn;
 unsigned long spanned_pages;
 unsigned long present_pages;
 const char *name;
} __attribute__((__aligned__(1 << (6))));
typedef enum {
 ZONE_RECLAIM_LOCKED,
 ZONE_OOM_LOCKED,
} zone_flags_t;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
unsigned long zone_nr_free_pages(struct zone *zone);
struct zonelist_cache;
struct zoneref {
 struct zone *zone;
 int zone_idx;
};
struct zonelist {
 struct zonelist_cache *zlcache_ptr;
 struct zoneref _zonerefs[((1 << 0) * 4) + 1];
};
struct node_active_region {
 unsigned long start_pfn;
 unsigned long end_pfn;
 int nid;
};
extern struct page *mem_map;
struct bootmem_data;
typedef struct pglist_data {
 struct zone node_zones[4];
 struct zonelist node_zonelists[1];
 int nr_zones;
 struct page *node_mem_map;
 struct page_cgroup *node_page_cgroup;
 unsigned long node_start_pfn;
 unsigned long node_present_pages;
 unsigned long node_spanned_pages;
 int node_id;
 wait_queue_head_t kswapd_wait;
 struct task_struct *kswapd;
 int kswapd_max_order;
} pg_data_t;
struct srcu_struct_array {
 int c[2];
};
struct srcu_struct {
 int completed;
 struct srcu_struct_array *per_cpu_ref;
 struct mutex mutex;
};
int init_srcu_struct(struct srcu_struct *sp);
void cleanup_srcu_struct(struct srcu_struct *sp);
int __srcu_read_lock(struct srcu_struct *sp) ;
void __srcu_read_unlock(struct srcu_struct *sp, int idx) ;
void synchronize_srcu(struct srcu_struct *sp);
void synchronize_srcu_expedited(struct srcu_struct *sp);
long srcu_batches_completed(struct srcu_struct *sp);
// supprimed function
// supprimed function
// supprimed function
struct notifier_block {
 int (*notifier_call)(struct notifier_block *, unsigned long, void *);
 struct notifier_block *next;
 int priority;
};
struct atomic_notifier_head {
 spinlock_t lock;
 struct notifier_block *head;
};
struct blocking_notifier_head {
 struct rw_semaphore rwsem;
 struct notifier_block *head;
};
struct raw_notifier_head {
 struct notifier_block *head;
};
struct srcu_notifier_head {
 struct mutex mutex;
 struct srcu_struct srcu;
 struct notifier_block *head;
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
extern struct blocking_notifier_head reboot_notifier_list;
struct page;
struct zone;
struct pglist_data;
struct mem_section;
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct page *sparse_decode_mem_map(unsigned long coded_mem_map,
       unsigned long pnum);
extern struct mutex zonelists_mutex;
void get_zone_counts(unsigned long *active, unsigned long *inactive,
   unsigned long *free);
void build_all_zonelists(void *data);
void wakeup_kswapd(struct zone *zone, int order);
int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
  int classzone_idx, int alloc_flags);
enum memmap_context {
 MEMMAP_EARLY,
 MEMMAP_HOTPLUG,
};
// supprimed extern
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct ctl_table;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int,
     void *, size_t *, loff_t *);
// supprimed extern
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int,
     void *, size_t *, loff_t *);
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *, int,
     void *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
   void *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
   void *, size_t *, loff_t *);
// supprimed extern
// supprimed extern
extern struct pglist_data contig_page_data;
extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);
// supprimed function
// supprimed function
// supprimed function
struct zoneref *next_zones_zonelist(struct zoneref *z,
     enum zone_type highest_zoneidx,
     nodemask_t *nodes,
     struct zone **zone);
// supprimed function
void memory_present(int nid, unsigned long start, unsigned long end);
unsigned long __attribute__ ((__section__(".init.text"))) __attribute__((__cold__)) __attribute__((no_instrument_function)) node_memmap_size_bytes(int, unsigned long, unsigned long);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
struct pci_bus;
void x86_pci_root_bus_res_quirks(struct pci_bus *b);
// supprimed function
// supprimed function
int arch_update_cpu_topology(void);
// supprimed function
struct percpu_counter {
 spinlock_t lock;
 s64 count;
 struct list_head list;
 s32 *counters;
};
// supprimed extern
int __percpu_counter_init(struct percpu_counter *fbc, s64 amount,
     struct lock_class_key *key);
void percpu_counter_destroy(struct percpu_counter *fbc);
void percpu_counter_set(struct percpu_counter *fbc, s64 amount);
void __percpu_counter_add(struct percpu_counter *fbc, s64 amount, s32 batch);
s64 __percpu_counter_sum(struct percpu_counter *fbc);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct prop_global {
 int shift;
 struct percpu_counter events;
};
struct prop_descriptor {
 int index;
 struct prop_global pg[2];
 struct mutex mutex;
};
int prop_descriptor_init(struct prop_descriptor *pd, int shift);
void prop_change_shift(struct prop_descriptor *pd, int new_shift);
struct prop_local_percpu {
 struct percpu_counter events;
 int shift;
 unsigned long period;
 spinlock_t lock;
};
int prop_local_init_percpu(struct prop_local_percpu *pl);
void prop_local_destroy_percpu(struct prop_local_percpu *pl);
void __prop_inc_percpu(struct prop_descriptor *pd, struct prop_local_percpu *pl);
void prop_fraction_percpu(struct prop_descriptor *pd, struct prop_local_percpu *pl,
  long *numerator, long *denominator);
// supprimed function
void __prop_inc_percpu_max(struct prop_descriptor *pd,
      struct prop_local_percpu *pl, long frac);
struct prop_local_single {
 unsigned long events;
 unsigned long period;
 int shift;
 spinlock_t lock;
};
int prop_local_init_single(struct prop_local_single *pl);
void prop_local_destroy_single(struct prop_local_single *pl);
void __prop_inc_single(struct prop_descriptor *pd, struct prop_local_single *pl);
void prop_fraction_single(struct prop_descriptor *pd, struct prop_local_single *pl,
  long *numerator, long *denominator);
// supprimed function
typedef struct { int mode; } seccomp_t;
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct plist_head {
 struct list_head prio_list;
 struct list_head node_list;
};
struct plist_node {
 int prio;
 struct plist_head plist;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
struct rt_mutex {
 raw_spinlock_t wait_lock;
 struct plist_head wait_list;
 struct task_struct *owner;
};
struct rt_mutex_waiter;
struct hrtimer_sleeper;
 static inline int rt_mutex_debug_check_no_locks_freed(const void *from,
             unsigned long len)
 {
 return 0;
 }
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct rusage {
 struct timeval ru_utime;
 struct timeval ru_stime;
 long ru_maxrss;
 long ru_ixrss;
 long ru_idrss;
 long ru_isrss;
 long ru_minflt;
 long ru_majflt;
 long ru_nswap;
 long ru_inblock;
 long ru_oublock;
 long ru_msgsnd;
 long ru_msgrcv;
 long ru_nsignals;
 long ru_nvcsw;
 long ru_nivcsw;
};
struct rlimit {
 unsigned long rlim_cur;
 unsigned long rlim_max;
};
struct task_struct;
int getrusage(struct task_struct *p, int who, struct rusage *ru);
struct hrtimer_clock_base;
struct hrtimer_cpu_base;
enum hrtimer_mode {
 HRTIMER_MODE_ABS = 0x0,
 HRTIMER_MODE_REL = 0x1,
 HRTIMER_MODE_PINNED = 0x02,
 HRTIMER_MODE_ABS_PINNED = 0x02,
 HRTIMER_MODE_REL_PINNED = 0x03,
};
enum hrtimer_restart {
 HRTIMER_NORESTART,
 HRTIMER_RESTART,
};
struct hrtimer {
 struct rb_node node;
 ktime_t _expires;
 ktime_t _softexpires;
 enum hrtimer_restart (*function)(struct hrtimer *);
 struct hrtimer_clock_base *base;
 unsigned long state;
 int start_pid;
 void *start_site;
 char start_comm[16];
};
struct hrtimer_sleeper {
 struct hrtimer timer;
 struct task_struct *task;
};
struct hrtimer_clock_base {
 struct hrtimer_cpu_base *cpu_base;
 clockid_t index;
 struct rb_root active;
 struct rb_node *first;
 ktime_t resolution;
 ktime_t (*get_time)(void);
 ktime_t softirq_time;
 ktime_t offset;
};
struct hrtimer_cpu_base {
 raw_spinlock_t lock;
 struct hrtimer_clock_base clock_base[2];
 ktime_t expires_next;
 int hres_active;
 int hang_detected;
 unsigned long nr_events;
 unsigned long nr_retries;
 unsigned long nr_hangs;
 ktime_t max_hang_time;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct clock_event_device;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct task_io_accounting {
 u64 rchar;
 u64 wchar;
 u64 syscr;
 u64 syscw;
 u64 read_bytes;
 u64 write_bytes;
 u64 cancelled_write_bytes;
};
struct kobject;
struct module;
enum kobj_ns_type;
struct attribute {
 const char *name;
 struct module *owner;
 mode_t mode;
};
struct attribute_group {
 const char *name;
 mode_t (*is_visible)(struct kobject *,
           struct attribute *, int);
 struct attribute **attrs;
};
struct file;
struct vm_area_struct;
struct bin_attribute {
 struct attribute attr;
 size_t size;
 void *private1;
 ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *,
   char *, loff_t, size_t);
 ssize_t (*write)(struct file *,struct kobject *, struct bin_attribute *,
    char *, loff_t, size_t);
 int (*mmap)(struct file *, struct kobject *, struct bin_attribute *attr,
      struct vm_area_struct *vma);
};
struct sysfs_ops {
 ssize_t (*show)(struct kobject *, struct attribute *,char *);
 ssize_t (*store)(struct kobject *,struct attribute *,const char *, size_t);
};
struct sysfs_dirent;
int sysfs_schedule_callback(struct kobject *kobj, void (*func)(void *),
       void *data, struct module *owner);
int sysfs_create_dir(struct kobject *kobj);
void sysfs_remove_dir(struct kobject *kobj);
int sysfs_rename_dir(struct kobject *kobj, const char *new_name);
int sysfs_move_dir(struct kobject *kobj,
    struct kobject *new_parent_kobj);
int sysfs_create_file(struct kobject *kobj,
       const struct attribute *attr);
int sysfs_create_files(struct kobject *kobj,
       const struct attribute **attr);
int sysfs_chmod_file(struct kobject *kobj, struct attribute *attr,
      mode_t mode);
void sysfs_remove_file(struct kobject *kobj, const struct attribute *attr);
void sysfs_remove_files(struct kobject *kobj, const struct attribute **attr);
int sysfs_create_bin_file(struct kobject *kobj,
           const struct bin_attribute *attr);
void sysfs_remove_bin_file(struct kobject *kobj,
      const struct bin_attribute *attr);
int sysfs_create_link(struct kobject *kobj, struct kobject *target,
       const char *name);
int sysfs_create_link_nowarn(struct kobject *kobj,
       struct kobject *target,
       const char *name);
void sysfs_remove_link(struct kobject *kobj, const char *name);
int sysfs_rename_link(struct kobject *kobj, struct kobject *target,
   const char *old_name, const char *new_name);
void sysfs_delete_link(struct kobject *dir, struct kobject *targ,
   const char *name);
int sysfs_create_group(struct kobject *kobj,
        const struct attribute_group *grp);
int sysfs_update_group(struct kobject *kobj,
         const struct attribute_group *grp);
void sysfs_remove_group(struct kobject *kobj,
   const struct attribute_group *grp);
int sysfs_add_file_to_group(struct kobject *kobj,
   const struct attribute *attr, const char *group);
void sysfs_remove_file_from_group(struct kobject *kobj,
   const struct attribute *attr, const char *group);
void sysfs_notify(struct kobject *kobj, const char *dir, const char *attr);
void sysfs_notify_dirent(struct sysfs_dirent *sd);
struct sysfs_dirent *sysfs_get_dirent(struct sysfs_dirent *parent_sd,
          const void *ns,
          const unsigned char *name);
struct sysfs_dirent *sysfs_get(struct sysfs_dirent *sd);
void sysfs_put(struct sysfs_dirent *sd);
void sysfs_printk_last_file(void);
void sysfs_exit_ns(enum kobj_ns_type type, const void *tag);
int sysfs_init(void);
struct kref {
 atomic_t refcount;
};
void kref_init(struct kref *kref);
void kref_get(struct kref *kref);
int kref_put(struct kref *kref, void (*release) (struct kref *kref));
// supprimed extern
// supprimed extern
enum kobject_action {
 KOBJ_ADD,
 KOBJ_REMOVE,
 KOBJ_CHANGE,
 KOBJ_MOVE,
 KOBJ_ONLINE,
 KOBJ_OFFLINE,
 KOBJ_MAX
};
struct kobject {
 const char *name;
 struct list_head entry;
 struct kobject *parent;
 struct kset *kset;
 struct kobj_type *ktype;
 struct sysfs_dirent *sd;
 struct kref kref;
 unsigned int state_initialized:1;
 unsigned int state_in_sysfs:1;
 unsigned int state_add_uevent_sent:1;
 unsigned int state_remove_uevent_sent:1;
 unsigned int uevent_suppress:1;
};
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct kobject * kobject_create(void);
extern struct kobject * kobject_create_and_add(const char *name,
      struct kobject *parent);
// supprimed extern
// supprimed extern
extern struct kobject *kobject_get(struct kobject *kobj);
// supprimed extern
// supprimed extern
struct kobj_type {
 void (*release)(struct kobject *kobj);
 const struct sysfs_ops *sysfs_ops;
 struct attribute **default_attrs;
 const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
 const void *(*namespace1)(struct kobject *kobj);
};
struct kobj_uevent_env {
 char *envp[32];
 int envp_idx;
 char buf[2048];
 int buflen;
};
struct kset_uevent_ops {
 int (* const filter)(struct kset *kset, struct kobject *kobj);
 const char *(* const name)(struct kset *kset, struct kobject *kobj);
 int (* const uevent)(struct kset *kset, struct kobject *kobj,
        struct kobj_uevent_env *env);
};
struct kobj_attribute {
 struct attribute attr;
 ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
   char *buf);
 ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
    const char *buf, size_t count);
};
// supprimed extern
enum kobj_ns_type {
 KOBJ_NS_TYPE_NONE = 0,
 KOBJ_NS_TYPE_NET,
 KOBJ_NS_TYPES
};
struct sock;
struct kobj_ns_type_operations {
 enum kobj_ns_type type;
 const void *(*current_ns)(void);
 const void *(*netlink_ns)(struct sock *sk);
 const void *(*initial_ns)(void);
};
int kobj_ns_type_register(const struct kobj_ns_type_operations *ops);
int kobj_ns_type_registered(enum kobj_ns_type type);
const struct kobj_ns_type_operations *kobj_child_ns_ops(struct kobject *parent);
const struct kobj_ns_type_operations *kobj_ns_ops(struct kobject *kobj);
const void *kobj_ns_current(enum kobj_ns_type type);
const void *kobj_ns_netlink(enum kobj_ns_type type, struct sock *sk);
const void *kobj_ns_initial(enum kobj_ns_type type);
void kobj_ns_exit(enum kobj_ns_type type, const void *ns);
struct kset {
 struct list_head list;
 spinlock_t list_lock;
 struct kobject kobj;
 const struct kset_uevent_ops *uevent_ops;
};
// supprimed extern
// supprimed extern
// supprimed extern
extern struct kset * kset_create_and_add(const char *name,
      const struct kset_uevent_ops *u,
      struct kobject *parent_kobj);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
extern struct kobject *kset_find_obj(struct kset *, const char *);
extern struct kobject *kernel_kobj;
extern struct kobject *mm_kobj;
extern struct kobject *hypervisor_kobj;
extern struct kobject *power_kobj;
extern struct kobject *firmware_kobj;
int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
   char *envp[]);
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
 __attribute__((format (printf, 2, 3)));
int kobject_action_type(const char *buf, size_t count,
   enum kobject_action *type);
struct latency_record {
 unsigned long backtrace[12];
 unsigned int count;
 unsigned long time;
 unsigned long max;
};
struct task_struct;
// supprimed extern
void __account_scheduler_latency(struct task_struct *task, int usecs, int inter);
// supprimed function
void clear_all_latency_tracing(struct task_struct *p);
struct completion;
struct __sysctl_args {
 int *name;
 int nlen;
 void *oldval;
 size_t *oldlenp;
 void *newval;
 size_t newlen;
 unsigned long __unused[4];
};
enum
{
 CTL_KERN=1,
 CTL_VM=2,
 CTL_NET=3,
 CTL_PROC=4,
 CTL_FS=5,
 CTL_DEBUG=6,
 CTL_DEV=7,
 CTL_BUS=8,
 CTL_ABI=9,
 CTL_CPU=10,
 CTL_ARLAN=254,
 CTL_S390DBF=5677,
 CTL_SUNRPC=7249,
 CTL_PM=9899,
 CTL_FRV=9898,
};
enum
{
 CTL_BUS_ISA=1
};
enum
{
 INOTIFY_MAX_USER_INSTANCES=1,
 INOTIFY_MAX_USER_WATCHES=2,
 INOTIFY_MAX_QUEUED_EVENTS=3
};
enum
{
 KERN_OSTYPE=1,
 KERN_OSRELEASE=2,
 KERN_OSREV=3,
 KERN_VERSION=4,
 KERN_SECUREMASK=5,
 KERN_PROF=6,
 KERN_NODENAME=7,
 KERN_DOMAINNAME=8,
 KERN_PANIC=15,
 KERN_REALROOTDEV=16,
 KERN_SPARC_REBOOT=21,
 KERN_CTLALTDEL=22,
 KERN_PRINTK=23,
 KERN_NAMETRANS=24,
 KERN_PPC_HTABRECLAIM=25,
 KERN_PPC_ZEROPAGED=26,
 KERN_PPC_POWERSAVE_NAP=27,
 KERN_MODPROBE=28,
 KERN_SG_BIG_BUFF=29,
 KERN_ACCT=30,
 KERN_PPC_L2CR=31,
 KERN_RTSIGNR=32,
 KERN_RTSIGMAX=33,
 KERN_SHMMAX=34,
 KERN_MSGMAX=35,
 KERN_MSGMNB=36,
 KERN_MSGPOOL=37,
 KERN_SYSRQ=38,
 KERN_MAX_THREADS=39,
  KERN_RANDOM=40,
  KERN_SHMALL=41,
  KERN_MSGMNI=42,
  KERN_SEM=43,
  KERN_SPARC_STOP_A=44,
  KERN_SHMMNI=45,
 KERN_OVERFLOWUID=46,
 KERN_OVERFLOWGID=47,
 KERN_SHMPATH=48,
 KERN_HOTPLUG=49,
 KERN_IEEE_EMULATION_WARNINGS=50,
 KERN_S390_USER_DEBUG_LOGGING=51,
 KERN_CORE_USES_PID=52,
 KERN_TAINTED=53,
 KERN_CADPID=54,
 KERN_PIDMAX=55,
   KERN_CORE_PATTERN=56,
 KERN_PANIC_ON_OOPS=57,
 KERN_HPPA_PWRSW=58,
 KERN_HPPA_UNALIGNED=59,
 KERN_PRINTK_RATELIMIT=60,
 KERN_PRINTK_RATELIMIT_BURST=61,
 KERN_PTY=62,
 KERN_NGROUPS_MAX=63,
 KERN_SPARC_SCONS_PWROFF=64,
 KERN_HZ_TIMER=65,
 KERN_UNKNOWN_NMI_PANIC=66,
 KERN_BOOTLOADER_TYPE=67,
 KERN_RANDOMIZE=68,
 KERN_SETUID_DUMPABLE=69,
 KERN_SPIN_RETRY=70,
 KERN_ACPI_VIDEO_FLAGS=71,
 KERN_IA64_UNALIGNED=72,
 KERN_COMPAT_LOG=73,
 KERN_MAX_LOCK_DEPTH=74,
 KERN_NMI_WATCHDOG=75,
 KERN_PANIC_ON_NMI=76,
};
enum
{
 VM_UNUSED1=1,
 VM_UNUSED2=2,
 VM_UNUSED3=3,
 VM_UNUSED4=4,
 VM_OVERCOMMIT_MEMORY=5,
 VM_UNUSED5=6,
 VM_UNUSED7=7,
 VM_UNUSED8=8,
 VM_UNUSED9=9,
 VM_PAGE_CLUSTER=10,
 VM_DIRTY_BACKGROUND=11,
 VM_DIRTY_RATIO=12,
 VM_DIRTY_WB_CS=13,
 VM_DIRTY_EXPIRE_CS=14,
 VM_NR_PDFLUSH_THREADS=15,
 VM_OVERCOMMIT_RATIO=16,
 VM_PAGEBUF=17,
 VM_HUGETLB_PAGES=18,
 VM_SWAPPINESS=19,
 VM_LOWMEM_RESERVE_RATIO=20,
 VM_MIN_FREE_KBYTES=21,
 VM_MAX_MAP_COUNT=22,
 VM_LAPTOP_MODE=23,
 VM_BLOCK_DUMP=24,
 VM_HUGETLB_GROUP=25,
 VM_VFS_CACHE_PRESSURE=26,
 VM_LEGACY_VA_LAYOUT=27,
 VM_SWAP_TOKEN_TIMEOUT=28,
 VM_DROP_PAGECACHE=29,
 VM_PERCPU_PAGELIST_FRACTION=30,
 VM_ZONE_RECLAIM_MODE=31,
 VM_MIN_UNMAPPED=32,
 VM_PANIC_ON_OOM=33,
 VM_VDSO_ENABLED=34,
 VM_MIN_SLAB=35,
};
enum
{
 NET_CORE=1,
 NET_ETHER=2,
 NET_802=3,
 NET_UNIX=4,
 NET_IPV4=5,
 NET_IPX=6,
 NET_ATALK=7,
 NET_NETROM=8,
 NET_AX25=9,
 NET_BRIDGE=10,
 NET_ROSE=11,
 NET_IPV6=12,
 NET_X25=13,
 NET_TR=14,
 NET_DECNET=15,
 NET_ECONET=16,
 NET_SCTP=17,
 NET_LLC=18,
 NET_NETFILTER=19,
 NET_DCCP=20,
 NET_IRDA=412,
};
enum
{
 RANDOM_POOLSIZE=1,
 RANDOM_ENTROPY_COUNT=2,
 RANDOM_READ_THRESH=3,
 RANDOM_WRITE_THRESH=4,
 RANDOM_BOOT_ID=5,
 RANDOM_UUID=6
};
enum
{
 PTY_MAX=1,
 PTY_NR=2
};
enum
{
 BUS_ISA_MEM_BASE=1,
 BUS_ISA_PORT_BASE=2,
 BUS_ISA_PORT_SHIFT=3
};
enum
{
 NET_CORE_WMEM_MAX=1,
 NET_CORE_RMEM_MAX=2,
 NET_CORE_WMEM_DEFAULT=3,
 NET_CORE_RMEM_DEFAULT=4,
 NET_CORE_MAX_BACKLOG=6,
 NET_CORE_FASTROUTE=7,
 NET_CORE_MSG_COST=8,
 NET_CORE_MSG_BURST=9,
 NET_CORE_OPTMEM_MAX=10,
 NET_CORE_HOT_LIST_LENGTH=11,
 NET_CORE_DIVERT_VERSION=12,
 NET_CORE_NO_CONG_THRESH=13,
 NET_CORE_NO_CONG=14,
 NET_CORE_LO_CONG=15,
 NET_CORE_MOD_CONG=16,
 NET_CORE_DEV_WEIGHT=17,
 NET_CORE_SOMAXCONN=18,
 NET_CORE_BUDGET=19,
 NET_CORE_AEVENT_ETIME=20,
 NET_CORE_AEVENT_RSEQTH=21,
 NET_CORE_WARNINGS=22,
};
enum
{
 NET_UNIX_DESTROY_DELAY=1,
 NET_UNIX_DELETE_DELAY=2,
 NET_UNIX_MAX_DGRAM_QLEN=3,
};
enum
{
 NET_NF_CONNTRACK_MAX=1,
 NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT=2,
 NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV=3,
 NET_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED=4,
 NET_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT=5,
 NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT=6,
 NET_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK=7,
 NET_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT=8,
 NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE=9,
 NET_NF_CONNTRACK_UDP_TIMEOUT=10,
 NET_NF_CONNTRACK_UDP_TIMEOUT_STREAM=11,
 NET_NF_CONNTRACK_ICMP_TIMEOUT=12,
 NET_NF_CONNTRACK_GENERIC_TIMEOUT=13,
 NET_NF_CONNTRACK_BUCKETS=14,
 NET_NF_CONNTRACK_LOG_INVALID=15,
 NET_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS=16,
 NET_NF_CONNTRACK_TCP_LOOSE=17,
 NET_NF_CONNTRACK_TCP_BE_LIBERAL=18,
 NET_NF_CONNTRACK_TCP_MAX_RETRANS=19,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED=20,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT=21,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED=22,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED=23,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT=24,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD=25,
 NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT=26,
 NET_NF_CONNTRACK_COUNT=27,
 NET_NF_CONNTRACK_ICMPV6_TIMEOUT=28,
 NET_NF_CONNTRACK_FRAG6_TIMEOUT=29,
 NET_NF_CONNTRACK_FRAG6_LOW_THRESH=30,
 NET_NF_CONNTRACK_FRAG6_HIGH_THRESH=31,
 NET_NF_CONNTRACK_CHECKSUM=32,
};
enum
{
 NET_IPV4_FORWARD=8,
 NET_IPV4_DYNADDR=9,
 NET_IPV4_CONF=16,
 NET_IPV4_NEIGH=17,
 NET_IPV4_ROUTE=18,
 NET_IPV4_FIB_HASH=19,
 NET_IPV4_NETFILTER=20,
 NET_IPV4_TCP_TIMESTAMPS=33,
 NET_IPV4_TCP_WINDOW_SCALING=34,
 NET_IPV4_TCP_SACK=35,
 NET_IPV4_TCP_RETRANS_COLLAPSE=36,
 NET_IPV4_DEFAULT_TTL=37,
 NET_IPV4_AUTOCONFIG=38,
 NET_IPV4_NO_PMTU_DISC=39,
 NET_IPV4_TCP_SYN_RETRIES=40,
 NET_IPV4_IPFRAG_HIGH_THRESH=41,
 NET_IPV4_IPFRAG_LOW_THRESH=42,
 NET_IPV4_IPFRAG_TIME=43,
 NET_IPV4_TCP_MAX_KA_PROBES=44,
 NET_IPV4_TCP_KEEPALIVE_TIME=45,
 NET_IPV4_TCP_KEEPALIVE_PROBES=46,
 NET_IPV4_TCP_RETRIES1=47,
 NET_IPV4_TCP_RETRIES2=48,
 NET_IPV4_TCP_FIN_TIMEOUT=49,
 NET_IPV4_IP_MASQ_DEBUG=50,
 NET_TCP_SYNCOOKIES=51,
 NET_TCP_STDURG=52,
 NET_TCP_RFC1337=53,
 NET_TCP_SYN_TAILDROP=54,
 NET_TCP_MAX_SYN_BACKLOG=55,
 NET_IPV4_LOCAL_PORT_RANGE=56,
 NET_IPV4_ICMP_ECHO_IGNORE_ALL=57,
 NET_IPV4_ICMP_ECHO_IGNORE_BROADCASTS=58,
 NET_IPV4_ICMP_SOURCEQUENCH_RATE=59,
 NET_IPV4_ICMP_DESTUNREACH_RATE=60,
 NET_IPV4_ICMP_TIMEEXCEED_RATE=61,
 NET_IPV4_ICMP_PARAMPROB_RATE=62,
 NET_IPV4_ICMP_ECHOREPLY_RATE=63,
 NET_IPV4_ICMP_IGNORE_BOGUS_ERROR_RESPONSES=64,
 NET_IPV4_IGMP_MAX_MEMBERSHIPS=65,
 NET_TCP_TW_RECYCLE=66,
 NET_IPV4_ALWAYS_DEFRAG=67,
 NET_IPV4_TCP_KEEPALIVE_INTVL=68,
 NET_IPV4_INET_PEER_THRESHOLD=69,
 NET_IPV4_INET_PEER_MINTTL=70,
 NET_IPV4_INET_PEER_MAXTTL=71,
 NET_IPV4_INET_PEER_GC_MINTIME=72,
 NET_IPV4_INET_PEER_GC_MAXTIME=73,
 NET_TCP_ORPHAN_RETRIES=74,
 NET_TCP_ABORT_ON_OVERFLOW=75,
 NET_TCP_SYNACK_RETRIES=76,
 NET_TCP_MAX_ORPHANS=77,
 NET_TCP_MAX_TW_BUCKETS=78,
 NET_TCP_FACK=79,
 NET_TCP_REORDERING=80,
 NET_TCP_ECN=81,
 NET_TCP_DSACK=82,
 NET_TCP_MEM=83,
 NET_TCP_WMEM=84,
 NET_TCP_RMEM=85,
 NET_TCP_APP_WIN=86,
 NET_TCP_ADV_WIN_SCALE=87,
 NET_IPV4_NONLOCAL_BIND=88,
 NET_IPV4_ICMP_RATELIMIT=89,
 NET_IPV4_ICMP_RATEMASK=90,
 NET_TCP_TW_REUSE=91,
 NET_TCP_FRTO=92,
 NET_TCP_LOW_LATENCY=93,
 NET_IPV4_IPFRAG_SECRET_INTERVAL=94,
 NET_IPV4_IGMP_MAX_MSF=96,
 NET_TCP_NO_METRICS_SAVE=97,
 NET_TCP_DEFAULT_WIN_SCALE=105,
 NET_TCP_MODERATE_RCVBUF=106,
 NET_TCP_TSO_WIN_DIVISOR=107,
 NET_TCP_BIC_BETA=108,
 NET_IPV4_ICMP_ERRORS_USE_INBOUND_IFADDR=109,
 NET_TCP_CONG_CONTROL=110,
 NET_TCP_ABC=111,
 NET_IPV4_IPFRAG_MAX_DIST=112,
  NET_TCP_MTU_PROBING=113,
 NET_TCP_BASE_MSS=114,
 NET_IPV4_TCP_WORKAROUND_SIGNED_WINDOWS=115,
 NET_TCP_DMA_COPYBREAK=116,
 NET_TCP_SLOW_START_AFTER_IDLE=117,
 NET_CIPSOV4_CACHE_ENABLE=118,
 NET_CIPSOV4_CACHE_BUCKET_SIZE=119,
 NET_CIPSOV4_RBM_OPTFMT=120,
 NET_CIPSOV4_RBM_STRICTVALID=121,
 NET_TCP_AVAIL_CONG_CONTROL=122,
 NET_TCP_ALLOWED_CONG_CONTROL=123,
 NET_TCP_MAX_SSTHRESH=124,
 NET_TCP_FRTO_RESPONSE=125,
};
enum {
 NET_IPV4_ROUTE_FLUSH=1,
 NET_IPV4_ROUTE_MIN_DELAY=2,
 NET_IPV4_ROUTE_MAX_DELAY=3,
 NET_IPV4_ROUTE_GC_THRESH=4,
 NET_IPV4_ROUTE_MAX_SIZE=5,
 NET_IPV4_ROUTE_GC_MIN_INTERVAL=6,
 NET_IPV4_ROUTE_GC_TIMEOUT=7,
 NET_IPV4_ROUTE_GC_INTERVAL=8,
 NET_IPV4_ROUTE_REDIRECT_LOAD=9,
 NET_IPV4_ROUTE_REDIRECT_NUMBER=10,
 NET_IPV4_ROUTE_REDIRECT_SILENCE=11,
 NET_IPV4_ROUTE_ERROR_COST=12,
 NET_IPV4_ROUTE_ERROR_BURST=13,
 NET_IPV4_ROUTE_GC_ELASTICITY=14,
 NET_IPV4_ROUTE_MTU_EXPIRES=15,
 NET_IPV4_ROUTE_MIN_PMTU=16,
 NET_IPV4_ROUTE_MIN_ADVMSS=17,
 NET_IPV4_ROUTE_SECRET_INTERVAL=18,
 NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS=19,
};
enum
{
 NET_PROTO_CONF_ALL=-2,
 NET_PROTO_CONF_DEFAULT=-3
};
enum
{
 NET_IPV4_CONF_FORWARDING=1,
 NET_IPV4_CONF_MC_FORWARDING=2,
 NET_IPV4_CONF_PROXY_ARP=3,
 NET_IPV4_CONF_ACCEPT_REDIRECTS=4,
 NET_IPV4_CONF_SECURE_REDIRECTS=5,
 NET_IPV4_CONF_SEND_REDIRECTS=6,
 NET_IPV4_CONF_SHARED_MEDIA=7,
 NET_IPV4_CONF_RP_FILTER=8,
 NET_IPV4_CONF_ACCEPT_SOURCE_ROUTE=9,
 NET_IPV4_CONF_BOOTP_RELAY=10,
 NET_IPV4_CONF_LOG_MARTIANS=11,
 NET_IPV4_CONF_TAG=12,
 NET_IPV4_CONF_ARPFILTER=13,
 NET_IPV4_CONF_MEDIUM_ID=14,
 NET_IPV4_CONF_NOXFRM=15,
 NET_IPV4_CONF_NOPOLICY=16,
 NET_IPV4_CONF_FORCE_IGMP_VERSION=17,
 NET_IPV4_CONF_ARP_ANNOUNCE=18,
 NET_IPV4_CONF_ARP_IGNORE=19,
 NET_IPV4_CONF_PROMOTE_SECONDARIES=20,
 NET_IPV4_CONF_ARP_ACCEPT=21,
 NET_IPV4_CONF_ARP_NOTIFY=22,
};
enum
{
 NET_IPV4_NF_CONNTRACK_MAX=1,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT=2,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV=3,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED=4,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT=5,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT=6,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK=7,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT=8,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE=9,
 NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT=10,
 NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT_STREAM=11,
 NET_IPV4_NF_CONNTRACK_ICMP_TIMEOUT=12,
 NET_IPV4_NF_CONNTRACK_GENERIC_TIMEOUT=13,
 NET_IPV4_NF_CONNTRACK_BUCKETS=14,
 NET_IPV4_NF_CONNTRACK_LOG_INVALID=15,
 NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS=16,
 NET_IPV4_NF_CONNTRACK_TCP_LOOSE=17,
 NET_IPV4_NF_CONNTRACK_TCP_BE_LIBERAL=18,
 NET_IPV4_NF_CONNTRACK_TCP_MAX_RETRANS=19,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED=20,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT=21,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED=22,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED=23,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT=24,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD=25,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT=26,
 NET_IPV4_NF_CONNTRACK_COUNT=27,
 NET_IPV4_NF_CONNTRACK_CHECKSUM=28,
};
enum {
 NET_IPV6_CONF=16,
 NET_IPV6_NEIGH=17,
 NET_IPV6_ROUTE=18,
 NET_IPV6_ICMP=19,
 NET_IPV6_BINDV6ONLY=20,
 NET_IPV6_IP6FRAG_HIGH_THRESH=21,
 NET_IPV6_IP6FRAG_LOW_THRESH=22,
 NET_IPV6_IP6FRAG_TIME=23,
 NET_IPV6_IP6FRAG_SECRET_INTERVAL=24,
 NET_IPV6_MLD_MAX_MSF=25,
};
enum {
 NET_IPV6_ROUTE_FLUSH=1,
 NET_IPV6_ROUTE_GC_THRESH=2,
 NET_IPV6_ROUTE_MAX_SIZE=3,
 NET_IPV6_ROUTE_GC_MIN_INTERVAL=4,
 NET_IPV6_ROUTE_GC_TIMEOUT=5,
 NET_IPV6_ROUTE_GC_INTERVAL=6,
 NET_IPV6_ROUTE_GC_ELASTICITY=7,
 NET_IPV6_ROUTE_MTU_EXPIRES=8,
 NET_IPV6_ROUTE_MIN_ADVMSS=9,
 NET_IPV6_ROUTE_GC_MIN_INTERVAL_MS=10
};
enum {
 NET_IPV6_FORWARDING=1,
 NET_IPV6_HOP_LIMIT=2,
 NET_IPV6_MTU=3,
 NET_IPV6_ACCEPT_RA=4,
 NET_IPV6_ACCEPT_REDIRECTS=5,
 NET_IPV6_AUTOCONF=6,
 NET_IPV6_DAD_TRANSMITS=7,
 NET_IPV6_RTR_SOLICITS=8,
 NET_IPV6_RTR_SOLICIT_INTERVAL=9,
 NET_IPV6_RTR_SOLICIT_DELAY=10,
 NET_IPV6_USE_TEMPADDR=11,
 NET_IPV6_TEMP_VALID_LFT=12,
 NET_IPV6_TEMP_PREFERED_LFT=13,
 NET_IPV6_REGEN_MAX_RETRY=14,
 NET_IPV6_MAX_DESYNC_FACTOR=15,
 NET_IPV6_MAX_ADDRESSES=16,
 NET_IPV6_FORCE_MLD_VERSION=17,
 NET_IPV6_ACCEPT_RA_DEFRTR=18,
 NET_IPV6_ACCEPT_RA_PINFO=19,
 NET_IPV6_ACCEPT_RA_RTR_PREF=20,
 NET_IPV6_RTR_PROBE_INTERVAL=21,
 NET_IPV6_ACCEPT_RA_RT_INFO_MAX_PLEN=22,
 NET_IPV6_PROXY_NDP=23,
 NET_IPV6_ACCEPT_SOURCE_ROUTE=25,
 __NET_IPV6_MAX
};
enum {
 NET_IPV6_ICMP_RATELIMIT=1
};
enum {
 NET_NEIGH_MCAST_SOLICIT=1,
 NET_NEIGH_UCAST_SOLICIT=2,
 NET_NEIGH_APP_SOLICIT=3,
 NET_NEIGH_RETRANS_TIME=4,
 NET_NEIGH_REACHABLE_TIME=5,
 NET_NEIGH_DELAY_PROBE_TIME=6,
 NET_NEIGH_GC_STALE_TIME=7,
 NET_NEIGH_UNRES_QLEN=8,
 NET_NEIGH_PROXY_QLEN=9,
 NET_NEIGH_ANYCAST_DELAY=10,
 NET_NEIGH_PROXY_DELAY=11,
 NET_NEIGH_LOCKTIME=12,
 NET_NEIGH_GC_INTERVAL=13,
 NET_NEIGH_GC_THRESH1=14,
 NET_NEIGH_GC_THRESH2=15,
 NET_NEIGH_GC_THRESH3=16,
 NET_NEIGH_RETRANS_TIME_MS=17,
 NET_NEIGH_REACHABLE_TIME_MS=18,
};
enum {
 NET_DCCP_DEFAULT=1,
};
enum {
 NET_IPX_PPROP_BROADCASTING=1,
 NET_IPX_FORWARDING=2
};
enum {
 NET_LLC2=1,
 NET_LLC_STATION=2,
};
enum {
 NET_LLC2_TIMEOUT=1,
};
enum {
 NET_LLC_STATION_ACK_TIMEOUT=1,
};
enum {
 NET_LLC2_ACK_TIMEOUT=1,
 NET_LLC2_P_TIMEOUT=2,
 NET_LLC2_REJ_TIMEOUT=3,
 NET_LLC2_BUSY_TIMEOUT=4,
};
enum {
 NET_ATALK_AARP_EXPIRY_TIME=1,
 NET_ATALK_AARP_TICK_TIME=2,
 NET_ATALK_AARP_RETRANSMIT_LIMIT=3,
 NET_ATALK_AARP_RESOLVE_TIME=4
};
enum {
 NET_NETROM_DEFAULT_PATH_QUALITY=1,
 NET_NETROM_OBSOLESCENCE_COUNT_INITIALISER=2,
 NET_NETROM_NETWORK_TTL_INITIALISER=3,
 NET_NETROM_TRANSPORT_TIMEOUT=4,
 NET_NETROM_TRANSPORT_MAXIMUM_TRIES=5,
 NET_NETROM_TRANSPORT_ACKNOWLEDGE_DELAY=6,
 NET_NETROM_TRANSPORT_BUSY_DELAY=7,
 NET_NETROM_TRANSPORT_REQUESTED_WINDOW_SIZE=8,
 NET_NETROM_TRANSPORT_NO_ACTIVITY_TIMEOUT=9,
 NET_NETROM_ROUTING_CONTROL=10,
 NET_NETROM_LINK_FAILS_COUNT=11,
 NET_NETROM_RESET=12
};
enum {
 NET_AX25_IP_DEFAULT_MODE=1,
 NET_AX25_DEFAULT_MODE=2,
 NET_AX25_BACKOFF_TYPE=3,
 NET_AX25_CONNECT_MODE=4,
 NET_AX25_STANDARD_WINDOW=5,
 NET_AX25_EXTENDED_WINDOW=6,
 NET_AX25_T1_TIMEOUT=7,
 NET_AX25_T2_TIMEOUT=8,
 NET_AX25_T3_TIMEOUT=9,
 NET_AX25_IDLE_TIMEOUT=10,
 NET_AX25_N2=11,
 NET_AX25_PACLEN=12,
 NET_AX25_PROTOCOL=13,
 NET_AX25_DAMA_SLAVE_TIMEOUT=14
};
enum {
 NET_ROSE_RESTART_REQUEST_TIMEOUT=1,
 NET_ROSE_CALL_REQUEST_TIMEOUT=2,
 NET_ROSE_RESET_REQUEST_TIMEOUT=3,
 NET_ROSE_CLEAR_REQUEST_TIMEOUT=4,
 NET_ROSE_ACK_HOLD_BACK_TIMEOUT=5,
 NET_ROSE_ROUTING_CONTROL=6,
 NET_ROSE_LINK_FAIL_TIMEOUT=7,
 NET_ROSE_MAX_VCS=8,
 NET_ROSE_WINDOW_SIZE=9,
 NET_ROSE_NO_ACTIVITY_TIMEOUT=10
};
enum {
 NET_X25_RESTART_REQUEST_TIMEOUT=1,
 NET_X25_CALL_REQUEST_TIMEOUT=2,
 NET_X25_RESET_REQUEST_TIMEOUT=3,
 NET_X25_CLEAR_REQUEST_TIMEOUT=4,
 NET_X25_ACK_HOLD_BACK_TIMEOUT=5,
 NET_X25_FORWARD=6
};
enum
{
 NET_TR_RIF_TIMEOUT=1
};
enum {
 NET_DECNET_NODE_TYPE = 1,
 NET_DECNET_NODE_ADDRESS = 2,
 NET_DECNET_NODE_NAME = 3,
 NET_DECNET_DEFAULT_DEVICE = 4,
 NET_DECNET_TIME_WAIT = 5,
 NET_DECNET_DN_COUNT = 6,
 NET_DECNET_DI_COUNT = 7,
 NET_DECNET_DR_COUNT = 8,
 NET_DECNET_DST_GC_INTERVAL = 9,
 NET_DECNET_CONF = 10,
 NET_DECNET_NO_FC_MAX_CWND = 11,
 NET_DECNET_MEM = 12,
 NET_DECNET_RMEM = 13,
 NET_DECNET_WMEM = 14,
 NET_DECNET_DEBUG_LEVEL = 255
};
enum {
 NET_DECNET_CONF_LOOPBACK = -2,
 NET_DECNET_CONF_DDCMP = -3,
 NET_DECNET_CONF_PPP = -4,
 NET_DECNET_CONF_X25 = -5,
 NET_DECNET_CONF_GRE = -6,
 NET_DECNET_CONF_ETHER = -7
};
enum {
 NET_DECNET_CONF_DEV_PRIORITY = 1,
 NET_DECNET_CONF_DEV_T1 = 2,
 NET_DECNET_CONF_DEV_T2 = 3,
 NET_DECNET_CONF_DEV_T3 = 4,
 NET_DECNET_CONF_DEV_FORWARDING = 5,
 NET_DECNET_CONF_DEV_BLKSIZE = 6,
 NET_DECNET_CONF_DEV_STATE = 7
};
enum {
 NET_SCTP_RTO_INITIAL = 1,
 NET_SCTP_RTO_MIN = 2,
 NET_SCTP_RTO_MAX = 3,
 NET_SCTP_RTO_ALPHA = 4,
 NET_SCTP_RTO_BETA = 5,
 NET_SCTP_VALID_COOKIE_LIFE = 6,
 NET_SCTP_ASSOCIATION_MAX_RETRANS = 7,
 NET_SCTP_PATH_MAX_RETRANS = 8,
 NET_SCTP_MAX_INIT_RETRANSMITS = 9,
 NET_SCTP_HB_INTERVAL = 10,
 NET_SCTP_PRESERVE_ENABLE = 11,
 NET_SCTP_MAX_BURST = 12,
 NET_SCTP_ADDIP_ENABLE = 13,
 NET_SCTP_PRSCTP_ENABLE = 14,
 NET_SCTP_SNDBUF_POLICY = 15,
 NET_SCTP_SACK_TIMEOUT = 16,
 NET_SCTP_RCVBUF_POLICY = 17,
};
enum {
 NET_BRIDGE_NF_CALL_ARPTABLES = 1,
 NET_BRIDGE_NF_CALL_IPTABLES = 2,
 NET_BRIDGE_NF_CALL_IP6TABLES = 3,
 NET_BRIDGE_NF_FILTER_VLAN_TAGGED = 4,
 NET_BRIDGE_NF_FILTER_PPPOE_TAGGED = 5,
};
enum {
 NET_IRDA_DISCOVERY=1,
 NET_IRDA_DEVNAME=2,
 NET_IRDA_DEBUG=3,
 NET_IRDA_FAST_POLL=4,
 NET_IRDA_DISCOVERY_SLOTS=5,
 NET_IRDA_DISCOVERY_TIMEOUT=6,
 NET_IRDA_SLOT_TIMEOUT=7,
 NET_IRDA_MAX_BAUD_RATE=8,
 NET_IRDA_MIN_TX_TURN_TIME=9,
 NET_IRDA_MAX_TX_DATA_SIZE=10,
 NET_IRDA_MAX_TX_WINDOW=11,
 NET_IRDA_MAX_NOREPLY_TIME=12,
 NET_IRDA_WARN_NOREPLY_TIME=13,
 NET_IRDA_LAP_KEEPALIVE_TIME=14,
};
enum
{
 FS_NRINODE=1,
 FS_STATINODE=2,
 FS_MAXINODE=3,
 FS_NRDQUOT=4,
 FS_MAXDQUOT=5,
 FS_NRFILE=6,
 FS_MAXFILE=7,
 FS_DENTRY=8,
 FS_NRSUPER=9,
 FS_MAXSUPER=10,
 FS_OVERFLOWUID=11,
 FS_OVERFLOWGID=12,
 FS_LEASES=13,
 FS_DIR_NOTIFY=14,
 FS_LEASE_TIME=15,
 FS_DQSTATS=16,
 FS_XFS=17,
 FS_AIO_NR=18,
 FS_AIO_MAX_NR=19,
 FS_INOTIFY=20,
 FS_OCFS2=988,
};
enum {
 FS_DQ_LOOKUPS = 1,
 FS_DQ_DROPS = 2,
 FS_DQ_READS = 3,
 FS_DQ_WRITES = 4,
 FS_DQ_CACHE_HITS = 5,
 FS_DQ_ALLOCATED = 6,
 FS_DQ_FREE = 7,
 FS_DQ_SYNCS = 8,
 FS_DQ_WARNINGS = 9,
};
enum {
 DEV_CDROM=1,
 DEV_HWMON=2,
 DEV_PARPORT=3,
 DEV_RAID=4,
 DEV_MAC_HID=5,
 DEV_SCSI=6,
 DEV_IPMI=7,
};
enum {
 DEV_CDROM_INFO=1,
 DEV_CDROM_AUTOCLOSE=2,
 DEV_CDROM_AUTOEJECT=3,
 DEV_CDROM_DEBUG=4,
 DEV_CDROM_LOCK=5,
 DEV_CDROM_CHECK_MEDIA=6
};
enum {
 DEV_PARPORT_DEFAULT=-3
};
enum {
 DEV_RAID_SPEED_LIMIT_MIN=1,
 DEV_RAID_SPEED_LIMIT_MAX=2
};
enum {
 DEV_PARPORT_DEFAULT_TIMESLICE=1,
 DEV_PARPORT_DEFAULT_SPINTIME=2
};
enum {
 DEV_PARPORT_SPINTIME=1,
 DEV_PARPORT_BASE_ADDR=2,
 DEV_PARPORT_IRQ=3,
 DEV_PARPORT_DMA=4,
 DEV_PARPORT_MODES=5,
 DEV_PARPORT_DEVICES=6,
 DEV_PARPORT_AUTOPROBE=16
};
enum {
 DEV_PARPORT_DEVICES_ACTIVE=-3,
};
enum {
 DEV_PARPORT_DEVICE_TIMESLICE=1,
};
enum {
 DEV_MAC_HID_KEYBOARD_SENDS_LINUX_KEYCODES=1,
 DEV_MAC_HID_KEYBOARD_LOCK_KEYCODES=2,
 DEV_MAC_HID_MOUSE_BUTTON_EMULATION=3,
 DEV_MAC_HID_MOUSE_BUTTON2_KEYCODE=4,
 DEV_MAC_HID_MOUSE_BUTTON3_KEYCODE=5,
 DEV_MAC_HID_ADB_MOUSE_SENDS_KEYCODES=6
};
enum {
 DEV_SCSI_LOGGING_LEVEL=1,
};
enum {
 DEV_IPMI_POWEROFF_POWERCYCLE=1,
};
enum
{
 ABI_DEFHANDLER_COFF=1,
 ABI_DEFHANDLER_ELF=2,
 ABI_DEFHANDLER_LCALL7=3,
 ABI_DEFHANDLER_LIBCSO=4,
 ABI_TRACE=5,
 ABI_FAKE_UTSNAME=6,
};
struct ctl_table;
struct nsproxy;
struct ctl_table_root;
struct ctl_table_set {
 struct list_head list;
 struct ctl_table_set *parent;
 int (*is_seen)(struct ctl_table_set *);
};
// supprimed extern
struct ctl_table_header;
// supprimed extern
// supprimed extern
// supprimed extern
extern struct ctl_table_header *sysctl_head_grab(struct ctl_table_header *);
extern struct ctl_table_header *sysctl_head_next(struct ctl_table_header *prev);
extern struct ctl_table_header *__sysctl_head_next(struct nsproxy *namespaces,
      struct ctl_table_header *prev);
// supprimed extern
// supprimed extern
typedef struct ctl_table ctl_table;
typedef int proc_handler_func; //(struct ctl_table *ctl, int write,     void *buffer, size_t *lenp, loff_t *ppos);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct ctl_table
{
 const char *procname;
 void *data;
 int maxlen;
 mode_t mode;
 struct ctl_table *child;
 struct ctl_table *parent;
 proc_handler_func *proc_handler;
 void *extra1;
 void *extra2;
};
struct ctl_table_root {
 struct list_head root_list;
 struct ctl_table_set default_set;
 struct ctl_table_set *(*lookup)(struct ctl_table_root *root,
        struct nsproxy *namespaces);
 int (*permissions)(struct ctl_table_root *root,
   struct nsproxy *namespaces, struct ctl_table *table);
};
struct ctl_table_header
{
 struct ctl_table *ctl_table;
 struct list_head ctl_entry;
 int used;
 int count;
 struct completion *unregistering;
 struct ctl_table *ctl_table_arg;
 struct ctl_table_root *root;
 struct ctl_table_set *set;
 struct ctl_table *attached_by;
 struct ctl_table *attached_to;
 struct ctl_table_header *parent;
};
struct ctl_path {
 const char *procname;
};
void register_sysctl_root(struct ctl_table_root *root);
struct ctl_table_header *__register_sysctl_paths(
 struct ctl_table_root *root, struct nsproxy *namespaces,
 const struct ctl_path *path, struct ctl_table *table);
struct ctl_table_header *register_sysctl_table(struct ctl_table * table);
struct ctl_table_header *register_sysctl_paths(const struct ctl_path *path,
      struct ctl_table *table);
void unregister_sysctl_table(struct ctl_table_header * table);
int sysctl_check_table(struct nsproxy *namespaces, struct ctl_table *table);
typedef int32_t key_serial_t;
typedef uint32_t key_perm_t;
struct key;
struct seq_file;
struct user_struct;
struct signal_struct;
struct cred;
struct key_type;
struct key_owner;
struct keyring_list;
struct keyring_name;
typedef struct __key_reference_with_attributes *key_ref_t;
// supprimed function
// supprimed function
// supprimed function
struct key {
 atomic_t usage;
 key_serial_t serial;
 struct rb_node serial_node;
 struct key_type *type;
 struct rw_semaphore sem;
 struct key_user *user;
 void *security;
 union {
  time_t expiry;
  time_t revoked_at;
 };
 uid_t uid;
 gid_t gid;
 key_perm_t perm;
 unsigned short quotalen;
 unsigned short datalen;
 unsigned long flags;
 char *description;
 union {
  struct list_head link;
  unsigned long x[2];
  void *p[2];
 } type_data;
 union {
  unsigned long value;
  void *data;
  struct keyring_list *subscriptions;
 } payload;
};
extern struct key *key_alloc(struct key_type *type,
        const char *desc,
        uid_t uid, gid_t gid,
        const struct cred *cred,
        key_perm_t perm,
        unsigned long flags);
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
extern struct key *request_key(struct key_type *type,
          const char *description,
          const char *callout_info);
extern struct key *request_key_with_auxdata(struct key_type *type,
         const char *description,
         const void *callout_info,
         size_t callout_len,
         void *aux);
extern struct key *request_key_async(struct key_type *type,
         const char *description,
         const void *callout_info,
         size_t callout_len);
extern struct key *request_key_async_with_auxdata(struct key_type *type,
        const char *description,
        const void *callout_info,
        size_t callout_len,
        void *aux);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct key *keyring_alloc(const char *description, uid_t uid, gid_t gid,
     const struct cred *cred,
     unsigned long flags,
     struct key *dest);
// supprimed extern
// supprimed extern
// supprimed extern
extern struct key *key_lookup(key_serial_t id);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct selinux_audit_rule;
struct audit_context;
struct kern_ipc_perm;
int selinux_string_to_sid(char *str, u32 *sid);
int selinux_secmark_relabel_packet_permission(u32 sid);
void selinux_secmark_refcount_inc(void);
void selinux_secmark_refcount_dec(void);
bool selinux_is_enabled(void);
struct user_struct;
struct cred;
struct inode;
struct group_info {
 atomic_t usage;
 int ngroups;
 int nblocks;
 gid_t small_block[32];
 gid_t *blocks[0];
};
// supprimed function
extern struct group_info *groups_alloc(int);
extern struct group_info init_groups;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct thread_group_cred {
 atomic_t usage;
 pid_t tgid;
 spinlock_t lock;
 struct key *session_keyring;
 struct key *process_keyring;
 struct rcu_head rcu;
};
struct cred {
 atomic_t usage;
 uid_t uid;
 gid_t gid;
 uid_t suid;
 gid_t sgid;
 uid_t euid;
 gid_t egid;
 uid_t fsuid;
 gid_t fsgid;
 unsigned securebits;
 kernel_cap_t cap_inheritable;
 kernel_cap_t cap_permitted;
 kernel_cap_t cap_effective;
 kernel_cap_t cap_bset;
 unsigned char jit_keyring;
 struct key *thread_keyring;
 struct key *request_key_auth;
 struct thread_group_cred *tgcred;
 void *security;
 struct user_struct *user;
 struct group_info *group_info;
 struct rcu_head rcu;
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct cred *cred_alloc_blank(void);
extern struct cred *prepare_creds(void);
extern struct cred *prepare_exec_creds(void);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct cred *prepare_kernel_cred(struct task_struct *);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct exec_domain;
struct futex_pi_state;
struct robust_list_head;
struct bio_list;
struct fs_struct;
struct perf_event_context;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct seq_file;
struct cfs_rq;
struct task_group;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct task_struct;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
void io_schedule(void);
long io_schedule_timeout(long timeout);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct nsproxy;
struct user_namespace;
// supprimed extern
typedef unsigned long aio_context_t;
enum {
 IOCB_CMD_PREAD = 0,
 IOCB_CMD_PWRITE = 1,
 IOCB_CMD_FSYNC = 2,
 IOCB_CMD_FDSYNC = 3,
 IOCB_CMD_NOOP = 6,
 IOCB_CMD_PREADV = 7,
 IOCB_CMD_PWRITEV = 8,
};
struct io_event {
 __u64 data;
 __u64 obj;
 __s64 res;
 __s64 res2;
};
struct iocb {
 __u64 aio_data;
 __u32 aio_key, aio_reserved1;
 __u16 aio_lio_opcode;
 __s16 aio_reqprio;
 __u32 aio_fildes;
 __u64 aio_buf;
 __u64 aio_nbytes;
 __s64 aio_offset;
 __u64 aio_reserved2;
 __u32 aio_flags;
 __u32 aio_resfd;
};
struct iovec
{
 void *iov_base;
 __kernel_size_t iov_len;
};
struct kvec {
 void *iov_base;
 size_t iov_len;
};
// supprimed function
unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to);
struct kioctx;
struct kiocb {
 struct list_head ki_run_list;
 unsigned long ki_flags;
 int ki_users;
 unsigned ki_key;
 struct file *ki_filp;
 struct kioctx *ki_ctx;
 int (*ki_cancel)(struct kiocb *, struct io_event *);
 ssize_t (*ki_retry)(struct kiocb *);
 void (*ki_dtor)(struct kiocb *);
 union {
  void *user;
  struct task_struct *tsk;
 } ki_obj;
 __u64 ki_user_data;
 loff_t ki_pos;
 void *private1;
 unsigned short ki_opcode;
 size_t ki_nbytes;
 char *ki_buf;
 size_t ki_left;
 struct iovec ki_inline_vec;
  struct iovec *ki_iovec;
  unsigned long ki_nr_segs;
  unsigned long ki_cur_seg;
 struct list_head ki_list;
 struct eventfd_ctx *ki_eventfd;
};
struct aio_ring {
 unsigned id;
 unsigned nr;
 unsigned head;
 unsigned tail;
 unsigned magic;
 unsigned compat_features;
 unsigned incompat_features;
 unsigned header_length;
 struct io_event io_events[0];
};
struct aio_ring_info {
 unsigned long mmap_base;
 unsigned long mmap_size;
 struct page **ring_pages;
 spinlock_t ring_lock;
 long nr_pages;
 unsigned nr, tail;
 struct page *internal_pages[8];
};
struct kioctx {
 atomic_t users;
 int dead;
 struct mm_struct *mm;
 unsigned long user_id;
 struct hlist_node list;
 wait_queue_head_t wait;
 spinlock_t ctx_lock;
 int reqs_active;
 struct list_head active_reqs;
 struct list_head run_list;
 unsigned max_reqs;
 struct aio_ring_info ring_info;
 struct delayed_work wq;
 struct rcu_head rcu_head;
};
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct mm_struct;
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct sighand_struct {
 atomic_t count;
 struct k_sigaction action[64];
 spinlock_t siglock;
 wait_queue_head_t signalfd_wqh;
};
struct pacct_struct {
 int ac_flag;
 long ac_exitcode;
 unsigned long ac_mem;
 cputime_t ac_utime, ac_stime;
 unsigned long ac_minflt, ac_majflt;
};
struct cpu_itimer {
 cputime_t expires;
 cputime_t incr;
 u32 error;
 u32 incr_error;
};
struct task_cputime {
 cputime_t utime;
 cputime_t stime;
 unsigned long long sum_exec_runtime;
};
struct thread_group_cputimer {
 struct task_cputime cputime;
 int running;
 spinlock_t lock;
};
struct signal_struct {
 atomic_t sigcnt;
 atomic_t live;
 int nr_threads;
 wait_queue_head_t wait_chldexit;
 struct task_struct *curr_target;
 struct sigpending shared_pending;
 int group_exit_code;
 int notify_count;
 struct task_struct *group_exit_task;
 int group_stop_count;
 unsigned int flags;
 struct list_head posix_timers;
 struct hrtimer real_timer;
 struct pid *leader_pid;
 ktime_t it_real_incr;
 struct cpu_itimer it[2];
 struct thread_group_cputimer cputimer;
 struct task_cputime cputime_expires;
 struct list_head cpu_timers[3];
 struct pid *tty_old_pgrp;
 int leader;
 struct tty_struct *tty;
 cputime_t utime, stime, cutime, cstime;
 cputime_t gtime;
 cputime_t cgtime;
 cputime_t prev_utime, prev_stime;
 unsigned long nvcsw, nivcsw, cnvcsw, cnivcsw;
 unsigned long min_flt, maj_flt, cmin_flt, cmaj_flt;
 unsigned long inblock, oublock, cinblock, coublock;
 unsigned long maxrss, cmaxrss;
 struct task_io_accounting ioac;
 unsigned long long sum_sched_runtime;
 struct rlimit rlim[16];
 struct pacct_struct pacct;
 struct taskstats *stats;
 unsigned audit_tty;
 struct tty_audit_buf *tty_audit_buf;
 int oom_adj;
};
// supprimed function
struct user_struct {
 atomic_t __count;
 atomic_t processes;
 atomic_t files;
 atomic_t sigpending;
 atomic_t inotify_watches;
 atomic_t inotify_devs;
 atomic_t epoll_watches;
 unsigned long mq_bytes;
 unsigned long locked_shm;
 struct key *uid_keyring;
 struct key *session_keyring;
 struct hlist_node uidhash_node;
 uid_t uid;
 struct user_namespace *user_ns;
 atomic_long_t locked_vm;
};
// supprimed extern
extern struct user_struct *find_user(uid_t);
extern struct user_struct root_user;
struct backing_dev_info;
struct reclaim_state;
struct sched_info {
 unsigned long pcount;
 unsigned long long run_delay;
 unsigned long long last_arrival,
      last_queued;
 unsigned int bkl_count;
};
struct task_delay_info {
 spinlock_t lock;
 unsigned int flags;
 struct timespec blkio_start, blkio_end;
 u64 blkio_delay;
 u64 swapin_delay;
 u32 blkio_count;
 u32 swapin_count;
 struct timespec freepages_start, freepages_end;
 u64 freepages_delay;
 u32 freepages_count;
};
// supprimed function
enum cpu_idle_type {
 CPU_IDLE,
 CPU_NOT_IDLE,
 CPU_NEWLY_IDLE,
 CPU_MAX_IDLE_TYPES
};
enum powersavings_balance_level {
 POWERSAVINGS_BALANCE_NONE = 0,
 POWERSAVINGS_BALANCE_BASIC,
 POWERSAVINGS_BALANCE_WAKEUP,
 MAX_POWERSAVINGS_BALANCE_LEVELS
};
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
struct sched_group {
 struct sched_group *next;
 unsigned int cpu_power;
 unsigned long cpumask[0];
};
// supprimed function
enum sched_domain_level {
 SD_LV_NONE = 0,
 SD_LV_SIBLING,
 SD_LV_MC,
 SD_LV_CPU,
 SD_LV_NODE,
 SD_LV_ALLNODES,
 SD_LV_MAX
};
struct sched_domain_attr {
 int relax_domain_level;
};
struct sched_domain {
 struct sched_domain *parent;
 struct sched_domain *child;
 struct sched_group *groups;
 unsigned long min_interval;
 unsigned long max_interval;
 unsigned int busy_factor;
 unsigned int imbalance_pct;
 unsigned int cache_nice_tries;
 unsigned int busy_idx;
 unsigned int idle_idx;
 unsigned int newidle_idx;
 unsigned int wake_idx;
 unsigned int forkexec_idx;
 unsigned int smt_gain;
 int flags;
 enum sched_domain_level level;
 unsigned long last_balance;
 unsigned int balance_interval;
 unsigned int nr_balance_failed;
 u64 last_update;
 unsigned int lb_count[CPU_MAX_IDLE_TYPES];
 unsigned int lb_failed[CPU_MAX_IDLE_TYPES];
 unsigned int lb_balanced[CPU_MAX_IDLE_TYPES];
 unsigned int lb_imbalance[CPU_MAX_IDLE_TYPES];
 unsigned int lb_gained[CPU_MAX_IDLE_TYPES];
 unsigned int lb_hot_gained[CPU_MAX_IDLE_TYPES];
 unsigned int lb_nobusyg[CPU_MAX_IDLE_TYPES];
 unsigned int lb_nobusyq[CPU_MAX_IDLE_TYPES];
 unsigned int alb_count;
 unsigned int alb_failed;
 unsigned int alb_pushed;
 unsigned int sbe_count;
 unsigned int sbe_balanced;
 unsigned int sbe_pushed;
 unsigned int sbf_count;
 unsigned int sbf_balanced;
 unsigned int sbf_pushed;
 unsigned int ttwu_wake_remote;
 unsigned int ttwu_move_affine;
 unsigned int ttwu_move_balance;
 char *name;
 unsigned int span_weight;
 unsigned long span[0];
};
// supprimed function
// supprimed extern
cpumask_var_t *alloc_sched_domains(unsigned int ndoms);
void free_sched_domains(cpumask_var_t doms[], unsigned int ndoms);
// supprimed function
unsigned long default_scale_freq_power(struct sched_domain *sd, int cpu);
unsigned long default_scale_smt_power(struct sched_domain *sd, int cpu);
struct io_context;
// supprimed function
struct audit_context;
struct mempolicy;
struct pipe_inode_info;
struct uts_namespace;
struct rq;
struct sched_domain;
struct sched_class {
 const struct sched_class *next;
 void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
 void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
 void (*yield_task) (struct rq *rq);
 void (*check_preempt_curr) (struct rq *rq, struct task_struct *p, int flags);
 struct task_struct * (*pick_next_task) (struct rq *rq);
 void (*put_prev_task) (struct rq *rq, struct task_struct *p);
 int (*select_task_rq)(struct rq *rq, struct task_struct *p,
          int sd_flag, int flags);
 void (*pre_schedule) (struct rq *this_rq, struct task_struct *task);
 void (*post_schedule) (struct rq *this_rq);
 void (*task_waking) (struct rq *this_rq, struct task_struct *task);
 void (*task_woken) (struct rq *this_rq, struct task_struct *task);
 void (*set_cpus_allowed)(struct task_struct *p,
     const struct cpumask *newmask);
 void (*rq_online)(struct rq *rq);
 void (*rq_offline)(struct rq *rq);
 void (*set_curr_task) (struct rq *rq);
 void (*task_tick) (struct rq *rq, struct task_struct *p, int queued);
 void (*task_fork) (struct task_struct *p);
 void (*switched_from) (struct rq *this_rq, struct task_struct *task,
          int running);
 void (*switched_to) (struct rq *this_rq, struct task_struct *task,
        int running);
 void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
        int oldprio, int running);
 unsigned int (*get_rr_interval) (struct rq *rq,
      struct task_struct *task);
 void (*moved_group) (struct task_struct *p, int on_rq);
};
struct load_weight {
 unsigned long weight, inv_weight;
};
struct sched_statistics {
 u64 wait_start;
 u64 wait_max;
 u64 wait_count;
 u64 wait_sum;
 u64 iowait_count;
 u64 iowait_sum;
 u64 sleep_start;
 u64 sleep_max;
 s64 sum_sleep_runtime;
 u64 block_start;
 u64 block_max;
 u64 exec_max;
 u64 slice_max;
 u64 nr_migrations_cold;
 u64 nr_failed_migrations_affine;
 u64 nr_failed_migrations_running;
 u64 nr_failed_migrations_hot;
 u64 nr_forced_migrations;
 u64 nr_wakeups;
 u64 nr_wakeups_sync;
 u64 nr_wakeups_migrate;
 u64 nr_wakeups_local;
 u64 nr_wakeups_remote;
 u64 nr_wakeups_affine;
 u64 nr_wakeups_affine_attempts;
 u64 nr_wakeups_passive;
 u64 nr_wakeups_idle;
};
struct sched_entity {
 struct load_weight load;
 struct rb_node run_node;
 struct list_head group_node;
 unsigned int on_rq;
 u64 exec_start;
 u64 sum_exec_runtime;
 u64 vruntime;
 u64 prev_sum_exec_runtime;
 u64 nr_migrations;
 struct sched_statistics statistics;
 struct sched_entity *parent;
 struct cfs_rq *cfs_rq;
 struct cfs_rq *my_q;
};
struct sched_rt_entity {
 struct list_head run_list;
 unsigned long timeout;
 unsigned int time_slice;
 int nr_cpus_allowed;
 struct sched_rt_entity *back;
 struct sched_rt_entity *parent;
 struct rt_rq *rt_rq;
 struct rt_rq *my_q;
};
struct rcu_node;
struct task_struct {
 volatile long state;
 void *stack;
 atomic_t usage;
 unsigned int flags;
 unsigned int ptrace;
 int lock_depth;
 int prio, static_prio, normal_prio;
 unsigned int rt_priority;
 const struct sched_class *sched_class;
 struct sched_entity se;
 struct sched_rt_entity rt;
 struct hlist_head preempt_notifiers;
 unsigned char fpu_counter;
 unsigned int btrace_seq;
 unsigned int policy;
 cpumask_t cpus_allowed;
 struct sched_info sched_info;
 struct list_head tasks;
 struct plist_node pushable_tasks;
 struct mm_struct *mm, *active_mm;
 struct task_rss_stat rss_stat;
 int exit_state;
 int exit_code, exit_signal;
 int pdeath_signal;
 unsigned int personality;
 unsigned did_exec:1;
 unsigned in_execve:1;
 unsigned in_iowait:1;
 unsigned sched_reset_on_fork:1;
 pid_t pid;
 pid_t tgid;
 unsigned long stack_canary;
 struct task_struct *real_parent;
 struct task_struct *parent;
 struct list_head children;
 struct list_head sibling;
 struct task_struct *group_leader;
 struct list_head ptraced;
 struct list_head ptrace_entry;
 struct pid_link pids[PIDTYPE_MAX];
 struct list_head thread_group;
 struct completion *vfork_done;
 int *set_child_tid;
 int *clear_child_tid;
 cputime_t utime, stime, utimescaled, stimescaled;
 cputime_t gtime;
 cputime_t prev_utime, prev_stime;
 unsigned long nvcsw, nivcsw;
 struct timespec start_time;
 struct timespec real_start_time;
 unsigned long min_flt, maj_flt;
 struct task_cputime cputime_expires;
 struct list_head cpu_timers[3];
 const struct cred *real_cred;
 const struct cred *cred;
 struct mutex cred_guard_mutex;
 struct cred *replacement_session_keyring;
 char comm[16];
 int link_count, total_link_count;
 struct sysv_sem sysvsem;
 unsigned long last_switch_count;
 struct thread_struct thread;
 struct fs_struct *fs;
 struct files_struct *files;
 struct nsproxy *nsproxy;
 struct signal_struct *signal;
 struct sighand_struct *sighand;
 sigset_t blocked, real_blocked;
 sigset_t saved_sigmask;
 struct sigpending pending;
 unsigned long sas_ss_sp;
 size_t sas_ss_size;
 int (*notifier)(void *priv);
 void *notifier_data;
 sigset_t *notifier_mask;
 struct audit_context *audit_context;
 uid_t loginuid;
 unsigned int sessionid;
 seccomp_t seccomp;
    u32 parent_exec_id;
    u32 self_exec_id;
 spinlock_t alloc_lock;
 struct irqaction *irqaction;
 raw_spinlock_t pi_lock;
 struct plist_head pi_waiters;
 struct rt_mutex_waiter *pi_blocked_on;
 void *journal_info;
 struct bio_list *bio_list;
 struct reclaim_state *reclaim_state;
 struct backing_dev_info *backing_dev_info;
 struct io_context *io_context;
 unsigned long ptrace_message;
 siginfo_t *last_siginfo;
 struct task_io_accounting ioac;
 u64 acct_rss_mem1;
 u64 acct_vm_mem1;
 cputime_t acct_timexpd;
 nodemask_t mems_allowed;
 int mems_allowed_change_disable;
 int cpuset_mem_spread_rotor;
 int cpuset_slab_spread_rotor;
 struct css_set *cgroups;
 struct list_head cg_list;
 struct robust_list_head *robust_list;
 struct list_head pi_state_list;
 struct futex_pi_state *pi_state_cache;
 struct perf_event_context *perf_event_ctxp;
 struct mutex perf_event_mutex;
 struct list_head perf_event_list;
 atomic_t fs_excl;
 struct rcu_head rcu;
 struct pipe_inode_info *splice_pipe;
 struct task_delay_info *delays;
 struct prop_local_single dirties;
 int latency_record_count;
 struct latency_record latency_record[32];
 unsigned long timer_slack_ns;
 unsigned long default_timer_slack_ns;
 struct list_head *scm_work_list;
 int curr_ret_stack;
 struct ftrace_ret_stack *ret_stack;
 unsigned long long ftrace_timestamp;
 atomic_t trace_overrun;
 atomic_t tracing_graph_pause;
 unsigned long trace;
 unsigned long trace_recursion;
 struct memcg_batch_info {
  int do_batch;
  struct mem_cgroup *memcg;
  unsigned long bytes;
  unsigned long memsw_bytes;
 } memcg_batch;
};
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
struct pid_namespace;
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
   struct pid_namespace *ns);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
pid_t task_tgid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
extern struct pid *cad_pid;
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
enum sched_tunable_scaling {
 SCHED_TUNABLESCALING_NONE,
 SCHED_TUNABLESCALING_LOG,
 SCHED_TUNABLESCALING_LINEAR,
 SCHED_TUNABLESCALING_END,
};
extern enum sched_tunable_scaling sysctl_sched_tunable_scaling;
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
int sched_proc_update_handler(struct ctl_table *table, int write,
  void *buffer, size_t *length,
  loff_t *ppos);
// supprimed function
// supprimed extern
// supprimed extern
int sched_rt_handler(struct ctl_table *table, int write,
  void *buffer, size_t *lenp,
  loff_t *ppos);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct task_struct *idle_task(int cpu);
extern struct task_struct *curr_task(int cpu);
// supprimed extern
void yield(void);
extern struct exec_domain default_exec_domain;
union thread_union {
 struct thread_info thread_info;
 unsigned long stack[(((1UL) << 12) << 1)/sizeof(long)];
};
// supprimed function
// supprimed extern
extern struct task_struct init_task;
extern struct mm_struct init_mm;
extern struct pid_namespace init_pid_ns;
extern struct task_struct *find_task_by_vpid(pid_t nr);
extern struct task_struct *find_task_by_pid_ns(pid_t nr,
  struct pid_namespace *ns);
// supprimed extern
extern struct user_struct * alloc_uid(struct user_namespace *, uid_t);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
 extern void kick_process(struct task_struct *tsk);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct sigqueue *sigqueue_alloc(void);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
extern struct mm_struct * mm_alloc(void);
// supprimed extern
// supprimed function
// supprimed extern
extern struct mm_struct *get_task_mm(struct task_struct *task);
// supprimed extern
extern struct mm_struct *dup_mm(struct task_struct *tsk);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
struct task_struct *fork_idle(int);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
extern struct sighand_struct *lock_task_sighand(struct task_struct *tsk,
       unsigned long *flags);
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
void thread_group_cputime(struct task_struct *tsk, struct task_cputime *times);
void thread_group_cputimer(struct task_struct *tsk, struct task_cputime *times);
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
extern struct task_group init_task_group;
extern struct task_group *sched_create_group(struct task_group *parent);
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
// supprimed extern
// supprimed extern
// supprimed extern
// supprimed function
// supprimed function
// supprimed function
// supprimed function
