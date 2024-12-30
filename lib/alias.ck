#!/bin/bash
source $NTHOME/lib/function.ck

print_warn_message_simple "CHECK alias"
check_alias() {
    busybox grep 'alias' ~/.bash* 
    #busybox grep 'alias' ~/.bash* | busybox grep -av bash_history
    print_warn_message_simple "Try Check with COMMAND ' alias -p ' manually"
    echo
}
choose_and_call_function_without_parament check_alias
