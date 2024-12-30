#!/bin/bash

source $NTHOME/lib/function.ck
source $NTHOME/lib/blacklist.ck
  
check_etc_rc.d(){
    echo "INFO: Files in direction /etc/rc.d/ is: "
    busybox find /etc/rc.d/ -type f | busybox xargs busybox ls -al
    echo
    check_inputfile_byloop
    echo 
}

check_etc_profile.d(){
    echo "INFO: Files in direction /etc/profile.d/ is: "
    busybox find /etc/profile.d/ -type f | busybox xargs busybox ls -al
    echo
    check_inputfile_byloop
    echo 
}

print_warn_message_simple "CHECK rc.d rc.local and more"

print_info_message_simple "CHECK chkconfig --list"
chkconfig --list

print_info_message_simple "CHECK /etc/rc.local"
choose_and_call_function_with_one_parament check_by_cat /etc/rc.local

print_info_message_simple "CHECK /etc/inittab"
choose_and_call_function_with_one_parament check_by_cat /etc/inittab

print_info_message_simple "CHECK /etc/profile"
choose_and_call_function_with_one_parament check_by_cat /etc/profile

print_info_message_simple "CHECK /etc/rc.d/"
choose_and_call_function_without_parament check_etc_rc.d
print_info_message_simple "FINISH CHECK /etc/rc.d/"

print_info_message_simple "CHECK /etc/profile.d/"
choose_and_call_function_without_parament check_etc_profile.d

print_info_message_simple "FINISH CHECK rc.d rc.local and more"

