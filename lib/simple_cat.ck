#!/bin/bash

source $NTHOME/lib/function.ck

print_warn_message_simple "CHECK "$1
choose_and_call_function_with_one_parament check_by_cat $1
