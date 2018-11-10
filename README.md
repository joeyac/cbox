# cbox
linux sandboxing by using seccomp-bpf and ptrace sandbox



### 总体流程
首先主进程fork出一个从进程，从进程依次设置以下限制：

- `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);`
- `ptrace(PTRACE_TRACEME, 0, NULL, NULL);`
- 从配置文件当中读取时间内存（注意这里的时间是cpu时间）等限制，使用`setrlimit`做出限制
- `chdir`、`chroot`: `chroot`需要额外权限，可能不会使用
- 重定向`stdin`, `stdout`, `stderr`
- 增加seccomp规则
- 给自己发送`SIGSTOP`信号，这一步是因为，父进程需要通过`ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);`来开始追踪子进程的非法系统调用，必须要在设置seccomp规则之后才能开始合法追踪，于是父进程可以先`wait`一下，如果获取到了子进程正常暂停，那么说明之前的限制都正确应用且此时可以开始追踪子进程。
- 调用`execve(config->file, config->argv, config->envp);`执行程序，注意在seccomp规则中需要额外增加一条允许`execve(config->file...)`这样的系统调用执行。另外注意调用execve之后，如果本身是被ptrace的进程，在执行成功execve之后，会发送一个`SIGTRAP`的信号。

主进程本身在fork之后，需要配合从进程进行一些处理：

- 首先调用一次`wait`，如果不是异常退出状态，说明限制正常应用，继续处理，否则退出程序。正常的信号应该为`SIGSTOP(18)`
- 设置ptrace追踪属性：`ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);`
- 在子进程`execve`之前，用`setpgid(child,child);`将子进程的组id改为它自己，这样方便使用`kill(-child, XXX)`来向子进程及其派生进程发送信号。
- 调用`ptrace(PTRACE_CONT, child, 0, 0);`，然后子程序应该执行到execve完成之后
- 调用`wait`获取状态，信号应该为`SIGTRAP(5)`
- 调用`ptrace(PTRACE_CONT, child, 0, 0);`，从这里开始子程序应该开始真正的执行过程
- 调用`wait`获取状态，此时获取到状态时应该有三种情况:
	- 正常退出 / 资源异常
	- 使用了非法的系统调用
	- 超过wall time限制

在最后`正常退出 / 资源异常`放在一起是因为这种情况下都可以从wait返回的status中拿到大部分信息；`使用了非法的系统调用`需要特殊处理一下并且手动终止程序；`超过wall time限制`则是使用`setitimer`设置定时器向自身发送`SIGALRM`信号，并在对应的信号处理函数中将子进程组全部关闭。