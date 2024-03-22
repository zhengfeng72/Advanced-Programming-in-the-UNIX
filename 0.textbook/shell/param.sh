#!/bin/sh

IFS='@'
echo "IFS=$IFS"
echo \$@="$@"
echo \$\*="$*"
echo Number of arguments = $#
echo 'argv[0]='$0
I=1
for argv in $*; do
	echo "argv[$I]=$argv"
	I=$((I+1))
done

