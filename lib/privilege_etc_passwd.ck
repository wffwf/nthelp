#!/bin/bash
source $NTHOME/lib/function.ck

print_warn_message_simple "CHECK SUPER ROOT"
check_super_root() {
    print_info_message_simple "Account with id 0"
    busybox awk -F: '$3==0{print $1}' /etc/passwd
    print_info_message_simple "Account with sudo"
    busybox cat  /etc/sudoers | busybox grep -v "^#\|^$" | busybox grep "ALL=(ALL)"

}
choose_and_call_function_without_parament check_super_root
