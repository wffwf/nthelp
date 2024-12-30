#!/bin/bash

source $NTHOME/lib/function.ck
source $NTHOME/lib/blacklist.ck
  
check_ps(){
    busybox ps  > $NTHOME/lib/tempinfo/busybox_ps.txt
    sleep 2
    ps -ef  > $NTHOME/lib/tempinfo/system_ps.txt
    busybox cat $NTHOME/lib/tempinfo/busybox_ps.txt | busybox grep -v busybox | busybox grep -v grep | busybox grep -v nthelp | busybox grep -v ps.ck | busybox awk '{print $1}' | sort -n > $NTHOME/lib/tempinfo/busybox_pid.txt
    busybox cat $NTHOME/lib/tempinfo/system_ps.txt | busybox grep -v "ps -ef" | busybox grep -v grep | busybox grep -v nthelp | busybox grep -v ps.ck | busybox awk '{print $2}' | sort -n > $NTHOME/lib/tempinfo/system_pid.txt
    busybox cat $NTHOME/lib/tempinfo/busybox_ps.txt
    print_warn_message_simple "the Different of buxybox ps and system ps is: "
    busybox diff $NTHOME/lib/tempinfo/busybox_pid.txt $NTHOME/lib/tempinfo/system_pid.txt

    print_warn_message_simple "the Different of proc pid and system ps is: "
    busybox ls /proc | busybox grep -E '^[0-9]+$' | sort -n > $NTHOME/lib/tempinfo/proc_pid.txt
    busybox diff $NTHOME/lib/tempinfo/proc_pid.txt $NTHOME/lib/tempinfo/system_pid.txt
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox lsof | busybox grep PID '"
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox pwdx PID '"
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox find /etc | xargs strings -f | busybox grep bad_filename '"
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox find ~ | xargs strings -f | busybox grep bad_filename '"
    touch $NTHOME/lib/tempinfo/weakps
    echo
}

print_warn_message_simple "CHECK ps"
choose_and_call_function_without_parament check_ps

if [ -f $NTHOME/lib/tempinfo/weakps ]; then
    check_black_ps_list_with_filename $NTHOME/lib/tempinfo/busybox_ps.txt
    busybox rm $NTHOME/lib/tempinfo/weakps
fi


