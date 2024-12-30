#!/bin/bash
source $NTHOME/lib/function.ck

print_warn_message_simple "SHOW os system CentOS/Ubuntu etc."
show_osinfo() {
    lsb_release -a
    busybox cat /etc/redhat_release
    busybox cat /proc/version
    busybox cat /etc/issue
    echo
}
choose_and_call_function_without_parament show_osinfo
