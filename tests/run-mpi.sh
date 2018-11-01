#!/bin/bash

workers=4
n=1000
seed=111
compiled=1
while getopts "w:n:s:c" arg
do
	case $arg in
		w) workers=$OPTARG;;
		n) n=$OPTARG;;
		s) seed=$OPTARG;;
		c) compiled=0;;
		?)
			echo "unknow argument"
			exit 1;;
	esac
done

if [ $compiled -eq 0 ]; then
	mpic++ qsort-mpi-simple.cpp -o bin/qsort-mpi.o
fi

if [ $compiled -eq 1 ] || [ $? -eq 0 ]; then
	mpiexec -n $workers bin/qsort-mpi.o $n $seed
	exit $?
else
	exit 2
fi

