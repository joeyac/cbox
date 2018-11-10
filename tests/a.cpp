#include <bits/stdc++.h>
#include <unistd.h>
#include <time.h>
using namespace std;
int main() {
	fprintf(stdout, "pgid = %d\n", getpgrp());
	fprintf(stdout, "something to stdout 1\n");
	sleep(5);
	fprintf(stdout, "something to stdout 2\n");
//	fprintf(stderr, "something to stderr\n");
	return 0;
}
