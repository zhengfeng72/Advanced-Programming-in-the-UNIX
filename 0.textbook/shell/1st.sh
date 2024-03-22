#!/bin/sh
# 1st.sh lines with leading pound sign are comments
for file in *; do
	echo $file	# comments are not required to start
			# from the very beginning of a line
done
exit 0

