#!/bin/sh

_VarDefault_="This is a test. Hello, World! Test"
Var=${Var:-$_VarDefault_}
echo "Var=<$Var>, Length=<${#Var}>"
echo "Remove T*e from head (#):  <${Var#T*e}>"
echo "Remove T*e from head (##): <${Var##T*e}>"
echo "Remove e*t from tail (%):  <${Var%e*t}>"
echo "Remove e*t from tail (%%): <${Var%%e*t}>"
echo "Remove [Tt][Ee][Ss][Tt] from tail (%%): <${Var%%[Tt][Ee][Ss][Tt]}>"
echo "Remove [Tt]??? from head (##): <${Var##[Tt]???}>"
echo "Remove [Tt]??? from tail (%%): <${Var%%[Tt]???}>"
