#!/bin/sh

foo() {
	echo params = $*
	return 0
}

foo 1 2 3 4 5 || echo "foo returns false"

