from collections import defaultdict

with open('whosdaboss.naboskabsliste') as f:
    data = [l.strip() for l in f.readlines() if l[0] != '#']

nodes = defaultdict(int)

for line in data:
    relations = line.split(' ')
    
    # Count outgoing nodes:
    nodes[relations[0]] += len(relations) - 1

    # Count ingoing nodes:
    for word in relations[1:]:
        nodes[word] += 1

# Find node with most in+out going nodes:
for node, _ in sorted(nodes.items(), key=lambda kv: -kv[1])[:1]:
    print(node)
