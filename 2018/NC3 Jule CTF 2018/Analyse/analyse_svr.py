#!/usr/bin/env python3
import csv, sys
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from math import isclose
from statistics import mean, median

def s2i(s):
    return float(s.replace(',', '.'))

data = list(csv.reader(open('analyse_svær.csv', newline=''), delimiter=';', quoting=csv.QUOTE_MINIMAL))  # , quotechar='"'
M = np.array([[s2i(col) for col in row[1:]] for row in data])

for col in range(M.shape[1]):
    row = M[:,col] / np.linalg.norm(M[:,col])
    vals = sorted(row)
    plt.annotate(col, xy=(0, vals[0]))
    plt.annotate(col, xy=(len(vals), vals[-1]))
    plt.plot(range(len(vals)), vals, label=str(col))

plt.grid(True)
plt.show()

weird_cols = [2, 17, 22, 55, 69, 92, 95]

median = median(np.mean(M[:,col]) for col in range(M.shape[1]))
spikes = []

plot = defaultdict(int)
for col in range(M.shape[1]):
    plot[col] = mean(M[:,col])

    if not isclose(plot[col], median, rel_tol=0.6):
        spikes.append({'col': col, 'y': plot[col]})    

X = sorted(plot.keys())
Y = [plot[x] for x in X]

for weird_col in weird_cols:
    plt.annotate(' ', xy=(weird_col, plot[weird_col]), arrowprops=dict(facecolor='black', shrink=0.05))

for spike in spikes:
    plt.annotate(spike['col'], xy=(spike['col'], spike['y']))

plt.plot(X, Y)
plt.xticks([x for x in X if x % 2 == 0])
plt.grid(True)
plt.yscale('log', basey=2)
plt.show()
