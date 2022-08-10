# Syscall_Hiding

基于 https://passthehashbrowns.github.io/hiding-your-syscalls 想法的完整代码实现
在此基础上优化了部分代码，使其可以获取指定API的地址，并动态构造新的syscall stub，以躲避Frida的检测。
