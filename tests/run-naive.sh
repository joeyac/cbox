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
	g++ -std=c++11 qsort-naive-simple.cpp -o bin/qsort-naive.o -fopenmp
fi

if [ $compiled -eq 1 ] || [ $? -eq 0 ]; then
	bin/qsort-naive.o $n $seed
    exit $?
else
	exit 2
fi

