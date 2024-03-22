#!/bin/sh

Var1="1 2 3 4 5"
VAR1="a b c d e"

echo Var1 = $Var1
echo VAR1 = $VAR1

for x in $Var1; do
	echo -n "$x "
done
echo .

