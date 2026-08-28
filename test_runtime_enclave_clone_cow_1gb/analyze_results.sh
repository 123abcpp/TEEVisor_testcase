#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
input="${1:-${script_dir}/results.csv}"
threshold="${2:-1}"
sample_ms="${3:-100}"
if [[ "${input}" == *.csv ]]; then
    default_timing_input="${input%.csv}_timing.csv"
else
    default_timing_input="${input}_timing.csv"
fi
timing_input="${4:-${default_timing_input}}"
tsc_ghz="${5:-3.0}"

if [[ ! -f "${input}" ]]; then
    echo "Result file not found: ${input}" >&2
    exit 1
fi

if [[ ! "${threshold}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "CPU threshold must be a non-negative number." >&2
    exit 1
fi

if [[ ! "${sample_ms}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Sample interval must be a positive integer number of milliseconds." >&2
    exit 1
fi

if [[ ! "${tsc_ghz}" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] ||
   ! awk -v frequency="${tsc_ghz}" 'BEGIN { exit !(frequency > 0) }'; then
    echo "TSC frequency must be a positive number in GHz." >&2
    exit 1
fi

awk -F, -v threshold="${threshold}" -v sample_ms="${sample_ms}" '
function finish_cow( duration, average_cpu) {
    if (!active || sample_count == 0)
        return

    duration = sample_count * sample_ms / 1000
    average_cpu = cpu_sum / sample_count
    test_count++
    size_test_count[current_size]++
    duration_sum += duration
    test_cpu_sum += average_cpu
    all_cpu_sum += cpu_sum
    all_sample_count += sample_count
    size_duration_sum[current_size] += duration
    size_test_cpu_sum[current_size] += average_cpu
    size_cpu_sum[current_size] += cpu_sum
    size_sample_count[current_size] += sample_count

    printf "%-9d %-6d %-12.3f %-12.2f\n", current_size, \
           size_test_count[current_size], duration, average_cpu

    active = 0
    sample_count = 0
    cpu_sum = 0
    pending_count = 0
    pending_cpu = 0
}

function print_group(size) {
    if (!size_test_count[size])
        return

    printf "%-9d %-6d %-16.3f %-17.2f %.2f%%\n", size, \
           size_test_count[size],
           size_duration_sum[size] / size_test_count[size],
           size_test_cpu_sum[size] / size_test_count[size],
           size_cpu_sum[size] / size_sample_count[size]
}

BEGIN {
    printf "%-9s %-6s %-12s %-12s\n", "size_mb", "test", \
           "cow_time_s", "avg_cpu_pct"
}

NR == 1 {
    if ($1 != "timestamp_ns" || $4 != "cpu_percent" || $5 != "user_size_mb") {
        print "Unexpected CSV header" > "/dev/stderr"
        exit 2
    }
    next
}

$1 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+([.][0-9]+)?$/ || $5 !~ /^[0-9]+$/ {
    next
}

{
    cpu = $4 + 0
    row_size = $5 + 0

    if (active && row_size != current_size)
        finish_cow()

    if (cpu > threshold) {
        if (!active) {
            active = 1
            current_size = row_size
            sample_count = 0
            cpu_sum = 0
        } else if (pending_count) {
            # Bridge one low sample inside an otherwise continuous COW burst.
            sample_count += pending_count
            cpu_sum += pending_cpu
        }

        pending_count = 0
        pending_cpu = 0
        sample_count++
        cpu_sum += cpu
        next
    }

    if (active) {
        pending_count++
        pending_cpu += cpu
        if (pending_count >= 2)
            finish_cow()
    }
}

END {
    finish_cow()

    if (test_count == 0) {
        print "No COW intervals found." > "/dev/stderr"
        exit 3
    }

    printf "\nCOW tests: %d\n", test_count
    printf "Average COW time: %.3f s\n", duration_sum / test_count
    printf "Average CPU per test: %.2f%%\n", test_cpu_sum / test_count
    printf "Time-weighted average CPU: %.2f%%\n", all_cpu_sum / all_sample_count

    printf "\n%-9s %-6s %-16s %-17s %s\n", "size_mb", "tests", \
           "avg_cow_time_s", "avg_cpu_per_test", "weighted_cpu"
    print_group(512)
    print_group(1024)
    print_group(2048)
}
' "${input}"

if [[ ! -f "${timing_input}" ]]; then
    echo
    echo "Timing CSV not found: ${timing_input}" >&2
    exit 0
fi

echo
awk -F, -v tsc_ghz="${tsc_ghz}" '
function print_group(size) {
    if (!count[size])
        return

    printf "%-9d %-6d %-22.3f %-16.6f %.3f\n", size, count[size], \
           creation_sum[size] / count[size] / cycles_per_ms,
           fork_sum[size] / count[size] / cycles_per_ms,
           cow_sum[size] / count[size] / cycles_per_ms
}

BEGIN {
    cycles_per_ms = tsc_ghz * 1000000
    printf "TSC frequency: %.3f GHz\n", tsc_ghz
    printf "%-9s %-6s %-22s %-16s %s\n", "size_mb", "round", \
           "enclave_create_ms", "fork_ms", "cow_ms"
}

NR == 1 {
    if ($1 != "round" || $2 != "user_size_mb" ||
        $3 != "enclave_creation_cycles" || $4 != "fork_cycles" ||
        $5 != "cow_trigger_cycles") {
        print "Unexpected timing CSV header" > "/dev/stderr"
        exit 2
    }
    next
}

$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ &&
$4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/ {
    size = $2 + 0
    count[size]++
    total_count++
    creation_sum[size] += $3
    fork_sum[size] += $4
    cow_sum[size] += $5
    total_creation += $3
    total_fork += $4
    total_cow += $5

    printf "%-9d %-6d %-22.3f %-16.6f %.3f\n", size, $1, \
           $3 / cycles_per_ms, $4 / cycles_per_ms, $5 / cycles_per_ms
}

END {
    if (!total_count) {
        print "No complete TSC measurements found." > "/dev/stderr"
        exit 3
    }

    printf "\nTSC measurements: %d\n", total_count
    printf "Average enclave creation: %.3f ms\n", \
           total_creation / total_count / cycles_per_ms
    printf "Average fork: %.6f ms\n", total_fork / total_count / cycles_per_ms
    printf "Average child COW trigger: %.3f ms\n", \
           total_cow / total_count / cycles_per_ms

    printf "\n%-9s %-6s %-22s %-16s %s\n", "size_mb", "tests", \
           "avg_enclave_ms", "avg_fork_ms", "avg_cow_ms"
    print_group(512)
    print_group(1024)
    print_group(2048)
}
' "${timing_input}"
