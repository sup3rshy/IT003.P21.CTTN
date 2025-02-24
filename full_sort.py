#!/usr/bin/python3 
import os 
def insertion_sort(arr):
    n = len(arr)
    for i in range(1, n):
        element = arr[i] 
        j = i - 1
        while j >= 0 and arr[j] > element:
            arr[j + 1] = arr[j] 
            j -= 1
        arr[j + 1] = element 

def shake_sort(arr):
    n = len(arr)
    swapped = True 
    l = 0 
    r = n - 1
    while swapped:
        swapped = False 
        for i in range(l, r):
            if arr[i] > arr[i + 1]:
                arr[i], arr[i + 1] = arr[i + 1], arr[i] 
                swapped = True 
        if swapped == False:
            break 
        r -= 1 
        for i in range(r - 1, l - 1, -1):
            if arr[i] > arr[i + 1]:
                arr[i], arr[i + 1] = arr[i + 1], arr[i] 
                swapped = True 
        l += 1

def interchange_sort(arr):
    n = len(arr)
    for i in range(n - 1):
        for j in range(i + 1, n):
            if arr[i] > arr[j]:
                arr[i], arr[j] = arr[j], arr[i]

def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        swapped = False 
        for j in range(n - 1 - i):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
                swapped = True 
        if swapped == False:
            break 

def partition_hoare(arr, low, high):
    pivot = arr[low]  # Chọn pivot là phần tử đầu tiên
    left = low - 1
    right = high + 1
    
    while True:
        while True:
            left += 1
            if arr[left] >= pivot:
                break
        while True:
            right -= 1
            if arr[right] <= pivot:
                break
        if left >= right:
            return right
        arr[left], arr[right] = arr[right], arr[left] 
        
def quicksort(arr, low, high):
    if low >= high:
        return 
    pivot = partition_hoare(arr, low, high)
    quicksort(arr, low, pivot)
    quicksort(arr, pivot + 1, high) 
     
def binary_insertion_sort(arr):
    n = len(arr)
    for i in range(1, n):
        l = 0
        r = i - 1 
        element = arr[i]
        while l <= r:
            mid = l + r >> 1
            if arr[mid] < element:
                l = mid + 1
            else:
                r = mid - 1 
        
        for j in range(i - 1, l - 1, -1):
            arr[j + 1] = arr[j]
            
        arr[l] = element

def shell_sort(arr):
    n = len(arr)
    gap = n // 2
    while gap > 0:
        for i in range(gap, n):
            element = arr[i]
            j = i

            while j >= gap and arr[j - gap] > element:
                arr[j] = arr[j - gap]
                j -= gap
                
            arr[j] = element 
            
        gap //= 2
    
def selection_sort(arr):
    n = len(arr)
    for i in range(n - 1):
        mi = i 
        for j in range(i + 1, n):
            if arr[j] < arr[mi]:
                mi = j
        arr[i], arr[mi] = arr[mi], arr[i]

def heapify(arr, n, i):
    root = i
    left = 2 * i + 1 
    right = 2 * i + 2 
    
    if left < n and arr[left] > arr[root]:
        root = left 
        
    if right < n and arr[right] > arr[root]:
        root = right 
    
    if root != i:
        arr[i], arr[root] = arr[root], arr[i]
        heapify(arr, n, root)
    
def heap_sort(arr):
    n = len(arr)
    for i in range(n // 2 - 1, - 1, -1):
        heapify(arr, n, i)
    
    for i in range(n - 1, 0, -1):
        arr[i], arr[0] = arr[0], arr[i]
        heapify(arr, i, 0)
    
def merge_sort(arr):
    if len(arr) <= 1:
        return arr
    n = len(arr) 
    mid = n >> 1
    left_arr = [arr[i] for i in range(0, mid)]
    right_arr = [arr[i] for i in range(mid, n)]
    left_arr = merge_sort(left_arr)
    right_arr = merge_sort(right_arr)
    i, j = 0, 0 
    n, m = len(left_arr), len(right_arr)
    result = []
    while i < n or j < m:
        if (i < n) and (j == m or left_arr[i] <= right_arr[j]):
            result.append(left_arr[i])
            i += 1 
        elif i == n or right_arr[j] <= left_arr[i]:
            result.append(right_arr[j])
            j += 1
        
    return result

def counting_sort_bruh(arr):
    n = len(arr)
    maxValue = max(arr)
    minValue = min(arr)
    length = maxValue - minValue + 1 
    freq = [0] * length 
    result = [0] * n
    # Count frequency of each element in an array
    for i in range(n):
        freq[arr[i] - minValue] += 1 
    # Dung prefix sum de xac dinh vi tri 
    for i in range(1, length):
        freq[i] += freq[i - 1]
    # Create sorted array 
    for i in range(n - 1, -1, -1):
        result[freq[arr[i] - minValue] - 1] = arr[i] 
        freq[arr[i] - minValue] -= 1 
    
    return result 

def counting_sort(arr, cur):
    n = len(arr)
    freq = [0] * 10
    result = [0] * n
    # Count frequency of each element in an array
    for i in range(n):
        if arr[i] < cur:
            x = 0
        else:
            x = (arr[i] // cur) % 10
        freq[x] += 1 
    # Dung prefix sum de xac dinh vi tri 
    for i in range(1, 10):
        freq[i] += freq[i - 1]
    # Create sorted array 
    for i in range(n - 1, -1, -1):
        if arr[i] < cur:
            x = 0
        else:
            x = (arr[i] // cur) % 10
        result[freq[x] - 1] = arr[i] 
        freq[x] -= 1 
        
    return result 

def radix_sort(arr):
    maxValue = max(arr) 
    cur = 1 
    while maxValue >= cur:
        arr = counting_sort(arr, cur)
        cur *= 10
    return arr 

import heapq

def k_way_merge(arrays):
    heap = []
    result = []
    
    for i, arr in enumerate(arrays):
        if arr:  
            heapq.heappush(heap, (arr[0], i, 0))  

    while heap:
        value, list_idx, element_idx = heapq.heappop(heap)  
        result.append(value)

        if element_idx + 1 < len(arrays[list_idx]):
            next_val = arrays[list_idx][element_idx + 1]
            heapq.heappush(heap, (next_val, list_idx, element_idx + 1))

    return result

def k_way_merge_sort(arr, k):
    if len(arr) <= 1:
        return arr

    # Split array into k parts 
    size = len(arr) // k
    subarrays = [arr[i * size: (i + 1) * size] for i in range(k - 1)]
    subarrays.append(arr[(k - 1) * size:])  

    sorted_subarrays = [k_way_merge_sort(sub, k) for sub in subarrays]

    # Merge 
    return k_way_merge(sorted_subarrays)

check = True 
for i in range(1000):
    bruh = list(os.urandom(1000))
    huh = sorted(bruh)
    bruh = k_way_merge_sort(bruh, 10)
    check &= (bruh == huh)

print(check) 
