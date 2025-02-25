#include <bits/stdc++.h>
using namespace std;
const int N = 1e6 + 5;
int n = 0;
double arr[N], left_arr[N], right_arr[N];
void merge_sort(int l, int r) {
    if (l == r) {
        return;
    }
    int mid = l + r >> 1;
    merge_sort(l, mid);
    merge_sort(mid + 1, r);
    for (int i = l; i <= mid; i++) {
        left_arr[i] = arr[i];
    }
    for (int i = mid + 1; i <= r; i++) {
        right_arr[i] = arr[i];
    }
    int cur = l, i = l, j = mid + 1;
    while (i <= mid || j <= r) {
        if ((i <= mid) && (j > r || left_arr[i] <= right_arr[j])) {
            arr[cur++] = left_arr[i++];
        } else if (i > mid || right_arr[j] < left_arr[i]) {
            arr[cur++] = right_arr[j++];
        }
    }
}
int main(int argc, char *argv[]) {
    freopen(argv[1], "r", stdin);
    double x;
    while (cin >> x) {
        arr[++n] = x;
    }
    auto start = chrono::steady_clock::now();
    merge_sort(1, n);
    auto end = chrono::steady_clock::now();
    auto sec = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << sec.count() << " ms\n";
    return 0;
}