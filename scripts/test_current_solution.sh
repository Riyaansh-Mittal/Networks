#! /bin/bash

tested_tmpfile="/tmp/tester.tmp1"

###########
# helpers #
###########

function usage {
  echo "usage: bash $0 [<options>] <test_id>"
  echo -e "ARGS"
  echo -e "\t<test_id>: ID of the test to be run among {$(echo $test_ids | sed 's/ /,/g')}."
  echo "OPTIONS"
  echo -e "\t-a\trun all tests, one after the other."
  echo -e "\t-h\tprints this help message."
  exit 0
}

function boldify {
  echo -e "\033[1m$1\033[0m"
}


function run_single_test {
  testid=$1
  comparison_script="$SCRIPT_DIR/show_diff_reports.py"

  # try to run the test
  cmd2run="simulator.py -c tests-configs/$testid*"
  [[ $testid == B* ]] && cmd2run="$cmd2run -o /tmp/test_script_config.json"
  echo -e "\n$(boldify "** Test $testid **")\n\nRunning python3 $cmd2run '>' $tested_tmpfile"
  python3 $cmd2run > $tested_tmpfile
  [[ $(echo $?) -gt 0 ]] && echo -e "Something went wrong when running the simulator\nAborting.." && exit 1

  # output comparison with model solution
  python3 $comparison_script $tested_tmpfile baseline-output/$testid*
  echo
}

########
# main #
########

test_ids="A1 A2 A3 A4 B1 B2 B3 B4"

# parse options
all_tests=""
while getopts "ha" opt; do
  case "$opt" in
  h)
    usage
    exit 0
    ;;
  a)
    all_tests="True"
    ;;
  esac
done
shift $((OPTIND -1))

# parse arguments
[[ $# -gt 1 ]] && usage && exit 1
if [[ -z "$all_tests" ]]; then
  [[ $# -lt 1 ]] && usage && exit 1
  [[ $# -gt 0 ]] && [[ -z $(echo $test_ids | grep "$1") ]] && echo -e "\nERROR: unknown test ID\n" && usage && exit 1
  [[ $# -gt 0 ]] && test_ids=$1
fi

# position in the right directory
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR/.."

# remove previous files (if any)
for file in $tested_tmpfile; do
  [[ -f $file ]] && rm $file
done

# run tests
for testid in $test_ids; do
  run_single_test $testid
done

