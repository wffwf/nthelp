#!/bin/bash

source $NTHOME/lib/function.ck
  
check_netstat(){
    busybox netstat -antp > $NTHOME/lib/tempinfo/busybox_netstat_antp.txt
    sleep 2
    netstat -antp > $NTHOME/lib/tempinfo/system_netstat_antp.txt
    busybox cat $NTHOME/lib/tempinfo/busybox_netstat_antp.txt | egrep "LISTEN|ESTABLISB" | awk '{print $3,$4,$6}' | sort > $NTHOME/lib/tempinfo/busybox_netstat.txt
    busybox cat $NTHOME/lib/tempinfo/system_netstat_antp.txt | egrep "LISTEN|ESTABLISB" | awk '{print $3,$4,$6}' | sort > $NTHOME/lib/tempinfo/system_netstat.txt
    cat $NTHOME/lib/tempinfo/busybox_netstat_antp.txt
    print_warn_message_simple "the Different of buxybox netstat and system netstat is: "
    busybox diff $NTHOME/lib/tempinfo/busybox_netstat.txt $NTHOME/lib/tempinfo/system_netstat.txt
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox lsof | busybox grep PID '"
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox find /etc | xargs strings -f | busybox grep bad_port '"
    print_info_message_simple "Try Check UNNormal PID with COMMAND ' busybox find ~ | xargs strings -f | busybox grep bad_port '"
    echo
}

print_warn_message_simple "CHECK netstat"
choose_and_call_function_without_parament check_netstat
