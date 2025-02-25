#include <bits/stdc++.h>
using namespace std;
const int N = 1e6 + 5;
int n = 0;
double arr[N];
int main(int argc, char *argv[]) {
    freopen(argv[1], "r", stdin);
    double x;
    while (cin >> x) {
        arr[++n] = x;
    }
    auto start = chrono::steady_clock::now();
    sort(arr + 1, arr + n + 1);
    auto end = chrono::steady_clock::now();
    auto sec = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << sec.count() << " ms\n";
    return 0;
}