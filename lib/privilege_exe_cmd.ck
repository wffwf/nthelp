#!/bin/bash
source $NTHOME/lib/function.ck

print_warn_message_simple "CHECK SUID EXE CMDS"
check_suid_cmds() {
    #busybox find / -user root -perm -4000 -print 2>/dev/null
    #busybox find / -user root -perm -4000 -exec ls -ldb {} \; 
    busybox find / -perm -u=s -type f 2>/dev/null
    #busybox find / -perm /4000 -type f
    sudo -l | grep NOPASSWD
    sudo -l
}
choose_and_call_function_without_parament check_suid_cmds
