#!/usr/bin/python3 
import numpy 
import datetime
import sys 

fileName = sys.argv[1]
data = open(f'{fileName}', 'r').read().split(' ')
arr = [float(x) for x in data]
start = datetime.datetime.now()
arr = numpy.sort(arr)
end = datetime.datetime.now()
sec = (end - start).total_seconds() * 1000
print(f'{int(sec)} ms')
