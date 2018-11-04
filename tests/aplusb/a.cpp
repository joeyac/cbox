/*
* Filename:    a.cpp
* Created:     Sunday, October 28, 2018 02:01:29 AM
* Author:      crazyX
* More:
*
*/
#include <bits/stdc++.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#define mp make_pair
#define pb push_back
#define fi first
#define se second
#define SZ(x) ((int) (x).size())
#define all(x) (x).begin(), (x).end()
#define sqr(x) ((x) * (x))
#define clr(a,b) (memset(a,b,sizeof(a)))
#define y0 y3487465
#define y1 y8687969
#define fastio std::ios::sync_with_stdio(false)

using namespace std;

#if __cplusplus <= 199711L
	#warning The program needs at least a C++11 compliant compiler
#else
	template<typename T, typename... Args>
	T min(T value, Args... args) { return min(value, min(args...)); }

	template<typename T, typename... Args>
	T max(T value, Args... args) { return max(value, min(args...)); }
#endif

typedef long long ll;

const int INF = 1e9 + 7;
const int maxn = 1e3 + 7;

int n, m;
void exe() {
	char cmd[100] = "/bin/ls";
	char *argv[] = { "ls", NULL };
	char *environ[] = { NULL };
	execve(cmd, argv, environ);
}
int main()
{
	exe();
	char cmd[100] = "./test";
	char *argv[] = { "test", NULL };
	char *environ[] = { NULL };
	execve(cmd, argv, { NULL });
//	while (cin >> n >> m) {
//		cout << n + m << endl;
//	}
	return 0;
}
