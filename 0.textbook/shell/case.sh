#!/bin/sh

echo "Please answer yes or no"
read yesno

case "$yesno" in
	yes)	echo "Yes!" ;;
	no)	echo "No!" ;;
	y)	echo "Yes!" ;;
	n)	echo "No!" ;;
	*)	echo "Answer not recognized" ;;
esac

exit 0

