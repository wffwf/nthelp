#!/bin/bash
source $NTHOME/lib/function.ck

print_warn_message_simple "CHECK ssh authorized_keys"
check_ssh() {
   busybox cat /etc/passwd | busybox cut -d: -f6 | busybox xargs -I {} sh -c 'if [ -f "{}/.ssh/authorized_keys" ]; then busybox echo "[!!!] 在用户 {} 下发现登录公钥：" && busybox cat "{}/.ssh/authorized_keys"; fi'
    echo
}
choose_and_call_function_without_parament check_ssh
