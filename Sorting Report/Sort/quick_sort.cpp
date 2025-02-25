#include <bits/stdc++.h>
using namespace std;
const int N = 1e6 + 5;
int n = 0;
double arr[N];
void quicksort(int l, int r) {
    double pivot = arr[l + r >> 1];
    int i = l, j = r;
    while (i < j) {
        while (arr[i] < pivot) {
            i++;
        }
        while (arr[j] > pivot) {
            j--;
        }
        if (i <= j) {
            swap(arr[i++], arr[j--]);
        }
    }
    if (i < r) {
        quicksort(i, r);
    }
    if (l < j) {
        quicksort(l, j);
    }
}
int main(int argc, char *argv[]) {
    freopen(argv[1], "r", stdin);
    double x;
    while (cin >> x) {
        arr[++n] = x;
    }
    auto start = chrono::steady_clock::now();
    quicksort(1, n);
    auto end = chrono::steady_clock::now();
    auto sec = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << sec.count() << " ms\n";
    return 0;
}