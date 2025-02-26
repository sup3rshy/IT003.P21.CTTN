#!/usr/bin/python3 
from random import random
from numpy import sort 
from os import urandom
from pwn import u32

for numTest in range(10):
    arr = [(u32(urandom(4)) + random()) for i in range(1000000)]
    if numTest == 0:
        arr = sort(arr)
    elif numTest == 1:
        arr = sort(arr)[::-1]
    open(f'Testcase/inp_{numTest + 1}.txt', "w").write(' '.join(str(x) for x in arr))
