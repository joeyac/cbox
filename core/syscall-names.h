#ifndef syscall_name
#define syscall_name
static const char *syscall_names[] = {
 [247] = "waitid",
 [75] = "fdatasync",
 [245] = "mq_getsetattr",
 [204] = "sched_getaffinity",
 [42] = "connect",
 [281] = "epoll_pwait",
 [175] = "init_module",
 [176] = "delete_module",
 [258] = "mkdirat",
 [130] = "rt_sigsuspend",
 [257] = "openat",
 [297] = "rt_tgsigqueueinfo",
 [303] = "name_to_handle_at",
 [174] = "create_module",
 [171] = "setdomainname",
 [2] = "open",
 [286] = "timerfd_settime",
 [191] = "getxattr",
 [34] = "pause",
 [65] = "semop",
 [168] = "swapoff",
 [214] = "epoll_ctl_old",
 [173] = "ioperm",
 [30] = "shmat",
 [252] = "ioprio_get",
 [141] = "setpriority",
 [129] = "rt_sigqueueinfo",
 [35] = "nanosleep",
 [67] = "shmdt",
 [300] = "fanotify_init",
 [198] = "lremovexattr",
 [0] = "read",
 [312] = "kcmp",
 [142] = "sched_setparam",
 [167] = "swapon",
 [208] = "io_getevents",
 [86] = "link",
 [224] = "timer_gettime",
 [307] = "sendmmsg",
 [283] = "timerfd_create",
 [186] = "gettid",
 [218] = "set_tid_address",
 [114] = "setregid",
 [322] = "execveat",
 [255] = "inotify_rm_watch",
 [324] = "membarrier",
 [241] = "mq_unlink",
 [94] = "lchown",
 [249] = "request_key",
 [199] = "fremovexattr",
 [177] = "get_kernel_syms",
 [83] = "mkdir",
 [66] = "semctl",
 [99] = "sysinfo",
 [318] = "getrandom",
 [132] = "utime",
 [7] = "poll",
 [242] = "mq_timedsend",
 [302] = "prlimit64",
 [287] = "timerfd_gettime",
 [197] = "removexattr",
 [294] = "inotify_init1",
 [64] = "semget",
 [180] = "nfsservctl",
 [254] = "inotify_add_watch",
 [298] = "perf_event_open",
 [207] = "io_destroy",
 [157] = "prctl",
 [127] = "rt_sigpending",
 [244] = "mq_notify",
 [296] = "pwritev",
 [239] = "get_mempolicy",
 [179] = "quotactl",
 [233] = "epoll_ctl",
 [184] = "tuxcall",
 [117] = "setresuid",
 [27] = "mincore",
 [15] = "rt_sigreturn",
 [215] = "epoll_wait_old",
 [219] = "restart_syscall",
 [310] = "process_vm_readv",
 [153] = "vhangup",
 [178] = "query_module",
 [17] = "pread64",
 [264] = "renameat",
 [229] = "clock_getres",
 [231] = "exit_group",
 [189] = "lsetxattr",
 [253] = "inotify_init",
 [165] = "mount",
 [61] = "wait4",
 [56] = "clone",
 [320] = "kexec_file_load",
 [23] = "select",
 [220] = "semtimedop",
 [103] = "syslog",
 [118] = "getresuid",
 [74] = "fsync",
 [143] = "sched_getparam",
 [3] = "close",
 [126] = "capset",
 [90] = "chmod",
 [78] = "getdents",
 [77] = "ftruncate",
 [28] = "madvise",
 [237] = "mbind",
 [263] = "unlinkat",
 [155] = "pivot_root",
 [47] = "recvmsg",
 [53] = "socketpair",
 [1] = "write",
 [110] = "getppid",
 [88] = "symlink",
 [8] = "lseek",
 [305] = "clock_adjtime",
 [272] = "unshare",
 [206] = "io_setup",
 [251] = "ioprio_set",
 [100] = "times",
 [205] = "set_thread_area",
 [137] = "statfs",
 [76] = "truncate",
 [102] = "getuid",
 [119] = "setresgid",
 [289] = "signalfd4",
 [128] = "rt_sigtimedwait",
 [274] = "get_robust_list",
 [169] = "reboot",
 [32] = "dup",
 [282] = "signalfd",
 [311] = "process_vm_writev",
 [71] = "msgctl",
 [10] = "mprotect",
 [140] = "getpriority",
 [13] = "rt_sigaction",
 [226] = "timer_delete",
 [11] = "munmap",
 [6] = "lstat",
 [25] = "mremap",
 [48] = "shutdown",
 [291] = "epoll_create1",
 [267] = "readlinkat",
 [268] = "fchmodat",
 [161] = "chroot",
 [192] = "lgetxattr",
 [68] = "msgget",
 [295] = "preadv",
 [70] = "msgrcv",
 [120] = "getresgid",
 [270] = "pselect6",
 [51] = "getsockname",
 [284] = "eventfd",
 [38] = "setitimer",
 [236] = "vserver",
 [146] = "sched_get_priority_max",
 [309] = "getcpu",
 [40] = "sendfile",
 [293] = "pipe2",
 [163] = "acct",
 [183] = "afs_syscall",
 [81] = "fchdir",
 [185] = "security",
 [149] = "mlock",
 [9] = "mmap",
 [235] = "utimes",
 [79] = "getcwd",
 [147] = "sched_get_priority_min",
 [182] = "putpmsg",
 [14] = "rt_sigprocmask",
 [43] = "accept",
 [227] = "clock_settime",
 [49] = "bind",
 [24] = "sched_yield",
 [21] = "access",
 [150] = "munlock",
 [33] = "dup2",
 [292] = "dup3",
 [22] = "pipe",
 [152] = "munlockall",
 [36] = "getitimer",
 [105] = "setuid",
 [104] = "getgid",
 [18] = "pwrite64",
 [181] = "getpmsg",
 [195] = "llistxattr",
 [317] = "seccomp",
 [89] = "readlink",
 [288] = "accept4",
 [93] = "fchown",
 [4] = "stat",
 [59] = "execve",
 [278] = "vmsplice",
 [277] = "sync_file_range",
 [314] = "sched_setattr",
 [275] = "splice",
 [95] = "umask",
 [304] = "open_by_handle_at",
 [261] = "futimesat",
 [46] = "sendmsg",
 [72] = "fcntl",
 [84] = "rmdir",
 [217] = "getdents64",
 [240] = "mq_open",
 [37] = "alarm",
 [202] = "futex",
 [158] = "arch_prctl",
 [166] = "umount2",
 [57] = "fork",
 [85] = "creat",
 [98] = "getrusage",
 [148] = "sched_rr_get_interval",
 [238] = "set_mempolicy",
 [16] = "ioctl",
 [262] = "newfstatat",
 [228] = "clock_gettime",
 [55] = "getsockopt",
 [154] = "modify_ldt",
 [265] = "linkat",
 [250] = "keyctl",
 [172] = "iopl",
 [203] = "sched_setaffinity",
 [60] = "exit",
 [315] = "sched_getattr",
 [144] = "sched_setscheduler",
 [209] = "io_submit",
 [266] = "symlinkat",
 [106] = "setgid",
 [276] = "tee",
 [280] = "utimensat",
 [279] = "move_pages",
 [259] = "mknodat",
 [62] = "kill",
 [325] = "mlock2",
 [271] = "ppoll",
 [243] = "mq_timedreceive",
 [109] = "setpgid",
 [211] = "get_thread_area",
 [58] = "vfork",
 [45] = "recvfrom",
 [187] = "readahead",
 [20] = "writev",
 [210] = "io_cancel",
 [69] = "msgsnd",
 [323] = "userfaultfd",
 [135] = "personality",
 [196] = "flistxattr",
 [151] = "mlockall",
 [136] = "ustat",
 [107] = "geteuid",
 [222] = "timer_create",
 [26] = "msync",
 [164] = "settimeofday",
 [190] = "fsetxattr",
 [212] = "lookup_dcookie",
 [44] = "sendto",
 [52] = "getpeername",
 [19] = "readv",
 [216] = "remap_file_pages",
 [116] = "setgroups",
 [145] = "sched_getscheduler",
 [139] = "sysfs",
 [80] = "chdir",
 [63] = "uname",
 [321] = "bpf",
 [122] = "setfsuid",
 [124] = "getsid",
 [82] = "rename",
 [12] = "brk",
 [230] = "clock_nanosleep",
 [188] = "setxattr",
 [159] = "adjtimex",
 [316] = "renameat2",
 [121] = "getpgid",
 [5] = "fstat",
 [115] = "getgroups",
 [131] = "sigaltstack",
 [92] = "chown",
 [225] = "timer_getoverrun",
 [260] = "fchownat",
 [134] = "uselib",
 [96] = "gettimeofday",
 [285] = "fallocate",
 [111] = "getpgrp",
 [299] = "recvmmsg",
 [290] = "eventfd2",
 [133] = "mknod",
 [269] = "faccessat",
 [50] = "listen",
 [138] = "fstatfs",
 [246] = "kexec_load",
 [319] = "memfd_create",
 [256] = "migrate_pages",
 [194] = "listxattr",
 [101] = "ptrace",
 [221] = "fadvise64",
 [31] = "shmctl",
 [108] = "getegid",
 [160] = "setrlimit",
 [201] = "time",
 [87] = "unlink",
 [113] = "setreuid",
 [156] = "_sysctl",
 [308] = "setns",
 [29] = "shmget",
 [193] = "fgetxattr",
 [91] = "fchmod",
 [223] = "timer_settime",
 [162] = "sync",
 [54] = "setsockopt",
 [41] = "socket",
 [301] = "fanotify_mark",
 [313] = "finit_module",
 [306] = "syncfs",
 [112] = "setsid",
 [123] = "setfsgid",
 [213] = "epoll_create",
 [234] = "tgkill",
 [73] = "flock",
 [125] = "capget",
 [39] = "getpid",
 [248] = "add_key",
 [97] = "getrlimit",
 [273] = "set_robust_list",
 [200] = "tkill",
 [232] = "epoll_wait",
 [170] = "sethostname",
};
#endif