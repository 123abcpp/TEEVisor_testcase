# eclone COW stress test

This test follows the same clone, pipe, and `ERESUME` flow as
`test_runtime_enclave_clone_cache`. It supports 512 MB, 1 GB, and 2 GB user
ranges. After `eclone`, only the child resumes, allocates all but 100 MB of the
user heap, and writes one byte in every consecutive 4 KiB page before exiting.
The parent remains outside the enclave and waits for the child to terminate.

Each round prints three serialized TSC measurements:

- `ENCLAVE_CREATION_CYCLES`: the complete `build_enclave()` call.
- `FORK_CYCLES`: the parent-side `fork()` call.
- `COW_TRIGGER_CYCLES`: the child-only consecutive-page write loop. Printing
  and enclave cleanup are outside this timing window.

The monitor writes scheduler samples to the requested CSV and writes the three
per-round counters to a companion file. For example, `results_512mb.csv` is
paired with `results_512mb_timing.csv`.

Build and run from this directory using one terminal:

```sh
make
sudo ./monitor_kenclaved.sh 5 512MB results_512mb.csv
sudo ./monitor_kenclaved.sh 5 1GB results_1gb.csv
sudo ./monitor_kenclaved.sh 5 2GB results_2gb.csv
```

Run all three sizes, ten rounds each, retain the size-specific raw files, combine
them into `results.csv` and `results_timing.csv`, and analyze the combined data:

```sh
sudo ./run_all_sizes.sh 10 0.1 30
```

The final argument is the per-round timeout in seconds.

The script attaches `bpftrace` scheduler probes first, runs `main`, and stops
sampling after all rounds finish. Each parent waits for its cloned child to exit
and performs the final synchronous driver close before the next round starts.
It records monotonic timestamp, PID, on-CPU runtime, and CPU percentage every
100 ms. The first argument is the number of rounds, and the second selects a
512 MB, 1 GB, or 2 GB user range. The optional third argument is the CSV path,
and the optional fourth argument changes the sampling interval in seconds. For
example, `sudo ./monitor_kenclaved.sh 5 1GB results.csv 0.2` runs five 1 GB
rounds and samples every 200 ms. Each CSV row includes `user_size_mb` so results
from multiple sizes can be combined and grouped. The driver names its page-sync
kernel thread `kenclaved`.

Analyze a combined result file using a 1% COW-start threshold and 100 ms samples:

```sh
./analyze_results.sh results.csv
```

The optional second and third arguments set the CPU threshold and sampling
interval in milliseconds, respectively. The analyzer groups its summary by
`user_size_mb`, treats a single low sample inside a COW burst as sampling noise,
and requires two consecutive samples at or below the threshold to finish a COW
interval. It also reads the matching `_timing.csv` file and reports average
enclave-creation, fork, and child-COW times by user size. It converts cycles to
milliseconds using a 3.0 GHz TSC by default. An optional fourth argument selects
a different timing CSV, and an optional fifth argument changes the TSC frequency
in GHz.
