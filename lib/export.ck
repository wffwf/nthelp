#!/bin/bash
source $NTHOME/lib/function.ck

print_warn_message_simple "CHECK export"
check_export() {
    busybox grep 'export' ~/.bash* 
    print_warn_message_simple "Try to fix with COMMAND ' unset ' "
    echo
}
choose_and_call_function_without_parament check_export
