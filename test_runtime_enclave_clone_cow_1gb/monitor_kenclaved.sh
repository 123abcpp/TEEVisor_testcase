#!/usr/bin/env bash
set -euo pipefail

rounds="${1:-1}"
user_size="${2:-2GB}"
output="${3:-kenclaved_cpu.csv}"
interval="${4:-0.1}"
round_timeout="${5:-30}"
thread_name="kenclaved"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! "${rounds}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Rounds must be a positive integer." >&2
    exit 1
fi

case "${user_size}" in
    512|512MB|512mb) user_size_mb=512 ;;
    1024|1GB|1gb) user_size_mb=1024 ;;
    2048|2GB|2gb) user_size_mb=2048 ;;
    *)
        echo "User size must be 512MB, 1GB, or 2GB." >&2
        exit 1
        ;;
esac

if [[ ! "${interval}" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]]; then
    echo "Sampling interval must be a positive number of seconds (for example, 0.1)." >&2
    exit 1
fi

if [[ ! "${round_timeout}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Round timeout must be a positive integer number of seconds." >&2
    exit 1
fi

interval_ms="$(awk -v seconds="${interval}" 'BEGIN {
    milliseconds = seconds * 1000
    if (milliseconds < 1 || milliseconds != int(milliseconds))
        exit 1
    printf "%d", milliseconds
}')" || {
    echo "Sampling interval must be at least 0.001 seconds and resolve to whole milliseconds." >&2
    exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script as root: sudo $0 [rounds] [512MB|1GB|2GB] [output.csv] [sample_seconds] [round_timeout_seconds]" >&2
    exit 1
fi

if [[ ! -x "${script_dir}/main" ]]; then
    echo "${script_dir}/main is missing; run 'make' in ${script_dir} first." >&2
    exit 1
fi

pid="$(pgrep -x "${thread_name}" | head -n 1 || true)"
if [[ -z "${pid}" ]]; then
    echo "Cannot find kernel thread '${thread_name}'. Is the TeeVisor driver loaded?" >&2
    exit 1
fi

if ! command -v bpftrace >/dev/null 2>&1; then
    echo "bpftrace is required." >&2
    exit 1
fi

if [[ "${output}" != /* ]]; then
    output="${script_dir}/${output}"
fi
if [[ "${output}" == *.csv ]]; then
    timing_output="${output%.csv}_timing.csv"
else
    timing_output="${output}_timing.csv"
fi

echo "Monitoring ${thread_name} (PID ${pid}) every ${interval_ms}ms for ${rounds} ${user_size_mb} MiB test round(s)."
echo "timestamp_ns,pid,runtime_ns,cpu_percent,user_size_mb" > "${output}"
echo "round,user_size_mb,enclave_creation_cycles,fork_cycles,cow_trigger_cycles" > "${timing_output}"

raw_output="$(mktemp /tmp/kenclaved-bpftrace.XXXXXX)"
bpf_program="
tracepoint:sched:sched_switch
/args->next_pid == ${pid}/
{
    @start = nsecs;
}

tracepoint:sched:sched_switch
/args->prev_pid == ${pid} && @start/
{
    \$now = nsecs;
    \$started = @start;
    \$delta = \$now - \$started;
    @runtime = @runtime + \$delta;
    delete(@start);
}

interval:ms:${interval_ms}
{
    \$now = nsecs;
    \$runtime = @runtime;

    if (@start) {
        \$started = @start;
        \$delta = \$now - \$started;
        \$runtime = \$runtime + \$delta;
        @start = \$now;
    }

    printf(\"%llu,%llu\\n\", \$now, \$runtime);
    @runtime = 0;
}
"

bpftrace -B none -e "${bpf_program}" > "${raw_output}" 2>&1 &
monitor_pid=$!
cleaned_up=0
round_log=""

cleanup()
{
    if [[ "${cleaned_up}" -ne 0 ]]; then
        return
    fi
    cleaned_up=1
    kill -INT "${monitor_pid}" 2>/dev/null || true
    wait "${monitor_pid}" 2>/dev/null || true
    awk -F, -v out="${output}" -v pid="${pid}" -v milliseconds="${interval_ms}" -v user_size_mb="${user_size_mb}" '
        $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {
            cpu = ($2 / (milliseconds * 1000000)) * 100
            printf "%s,%s,%s,%.2f,%s\n", $1, pid, $2, cpu, user_size_mb >> out
        }
    ' "${raw_output}"
    rm -f "${raw_output}"
    if [[ -n "${round_log}" ]]; then
        rm -f "${round_log}"
    fi
}
trap cleanup EXIT INT TERM

# Do not start the workload until bpftrace has attached both sched_switch probes.
for _ in $(seq 1 100); do
    if grep -q '^Attaching [0-9][0-9]* probes' "${raw_output}"; then
        break
    fi
    if ! kill -0 "${monitor_pid}" 2>/dev/null; then
        echo "bpftrace failed to start:" >&2
        cat "${raw_output}" >&2
        exit 1
    fi
    sleep 0.05
done

if ! grep -q '^Attaching [0-9][0-9]* probes' "${raw_output}"; then
    echo "Timed out waiting for bpftrace probes to attach." >&2
    exit 1
fi

test_status=0
for ((round = 1; round <= rounds; round++)); do
    echo "Starting test round ${round}/${rounds}."
    round_log="$(mktemp /tmp/eclone-cow-round.XXXXXX)"

    set +e
    (
        cd "${script_dir}"
        timeout --signal=TERM --kill-after=10s "${round_timeout}s" \
            ./main "${user_size_mb}"
    ) 2>&1 | tee "${round_log}"
    round_status=${PIPESTATUS[0]}
    set -e

    creation_cycles="$(awk -F= '$1 == "ENCLAVE_CREATION_CYCLES" { value=$2 } END { print value }' "${round_log}")"
    fork_cycles="$(awk -F= '$1 == "FORK_CYCLES" { value=$2 } END { print value }' "${round_log}")"
    cow_cycles="$(awk -F= '$1 == "COW_TRIGGER_CYCLES" { value=$2 } END { print value }' "${round_log}")"

    if [[ "${creation_cycles}" =~ ^[0-9]+$ &&
          "${fork_cycles}" =~ ^[0-9]+$ &&
          "${cow_cycles}" =~ ^[0-9]+$ ]]; then
        printf "%s,%s,%s,%s,%s\n" "${round}" "${user_size_mb}" \
            "${creation_cycles}" "${fork_cycles}" "${cow_cycles}" >> "${timing_output}"
    else
        echo "Round ${round} did not produce all three TSC measurements." >&2
        printf "%s,%s,%s,%s,%s\n" "${round}" "${user_size_mb}" \
            "${creation_cycles}" "${fork_cycles}" "${cow_cycles}" >> "${timing_output}"
        if [[ "${round_status}" -eq 0 ]]; then
            round_status=1
        fi
    fi
    rm -f "${round_log}"
    round_log=""

    if [[ "${round_status}" -ne 0 ]]; then
        echo "Test round ${round} exited with status ${round_status}." >&2
        test_status="${round_status}"
    fi

done

cleanup
trap - EXIT INT TERM

echo "CPU samples written to ${output}"
echo "TSC measurements written to ${timing_output}"
exit "${test_status}"
