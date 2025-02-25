#include <bits/stdc++.h>
using namespace std;
const int N = 1e6 + 5;
int n = 0;
double arr[N];
void heapify(int n, int i) {
    int largest = i;
    int l = 2 * i + 1;
    int r = 2 * i + 2;

    if (l < n && arr[l] > arr[largest])
        largest = l;

    if (r < n && arr[r] > arr[largest])
        largest = r;

    if (largest != i) {
        swap(arr[i], arr[largest]);
        heapify(n, largest);
    }
}

void heapsort(int n) {
    for (int i = n / 2 - 1; i >= 0; i--)
        heapify(n, i);

    for (int i = n - 1; i >= 0; i--) {
        swap(arr[0], arr[i]);
        heapify(i, 0);
    }
}
int main(int argc, char *argv[]) {
    freopen(argv[1], "r", stdin);
    double x;
    while (cin >> x) {
        arr[n++] = x;
    }
    auto start = chrono::steady_clock::now();
    heapsort(n);
    auto end = chrono::steady_clock::now();
    auto sec = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << sec.count() << " ms\n";   
    return 0;
}
