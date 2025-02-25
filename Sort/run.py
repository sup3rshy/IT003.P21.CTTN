#!/usr/bin/python3 
from pwn import * 

f = open("report.txt", "w")
sort_list = ['merge_sort', 'quick_sort', 'heap_sort', 'clib_sort', 'numpy_sort.py']
# context.log_level = "critical"
context.log_level = "debug"
p = process('Testcase/gentest.py')
p.wait()
p.close()
for name in sort_list:
    f.write(f'{name}:\n')
    for i in range(10):
        p = process([f'Sort/{name}', f'Testcase/inp_{i + 1}.txt'])
        p.wait()
        f.write(p.recvline().decode())
        p.close()
