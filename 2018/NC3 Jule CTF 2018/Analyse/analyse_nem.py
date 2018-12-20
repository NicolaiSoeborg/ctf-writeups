#!/usr/bin/env python3
import csv
import numpy as np
import matplotlib.pyplot as plt

def s2f(s):
    """ str-to-float """
    return float(s.replace(',', '.'))

data = list(csv.reader(open('analyse_nem.csv', newline=''), delimiter=';', quoting=csv.QUOTE_MINIMAL))
M = np.array([[s2f(col) for col in row[1:]] for row in data])

for col in range(M.shape[1]):
    row = M[:,col] / np.linalg.norm(M[:,col])
    vals = sorted(row)
    plt.annotate(col, xy=(0, vals[0]))
    plt.annotate(col, xy=(len(vals), vals[-1]))
    plt.plot(range(len(vals)), vals, label=str(col))

plt.grid(True)
plt.show()

weird_col = 66

for row in range(M.shape[0]):
    col_val = M[row,weird_col]
    idx = int(round(col_val - 1))
    print(data[idx][0], end='')
print('')
