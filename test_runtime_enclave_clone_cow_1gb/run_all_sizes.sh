#!/usr/bin/env bash
set -euo pipefail

rounds="${1:-10}"
sample_seconds="${2:-0.1}"
round_timeout="${3:-30}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script as root: sudo $0 [rounds] [sample_seconds] [round_timeout_seconds]" >&2
    exit 1
fi

for size in 512mb 1gb 2gb; do
    "${script_dir}/monitor_kenclaved.sh" "${rounds}" "${size}" \
        "results_${size}.csv" "${sample_seconds}" "${round_timeout}"
done

combined_cpu="$(mktemp "${script_dir}/.results.csv.XXXXXX")"
combined_timing="$(mktemp "${script_dir}/.results_timing.csv.XXXXXX")"

awk 'FNR == 1 && NR != 1 { next } { print }' \
    "${script_dir}/results_512mb.csv" \
    "${script_dir}/results_1gb.csv" \
    "${script_dir}/results_2gb.csv" > "${combined_cpu}"

awk 'FNR == 1 && NR != 1 { next } { print }' \
    "${script_dir}/results_512mb_timing.csv" \
    "${script_dir}/results_1gb_timing.csv" \
    "${script_dir}/results_2gb_timing.csv" > "${combined_timing}"

mv "${combined_cpu}" "${script_dir}/results.csv"
mv "${combined_timing}" "${script_dir}/results_timing.csv"

echo "Combined CPU samples written to ${script_dir}/results.csv"
echo "Combined TSC measurements written to ${script_dir}/results_timing.csv"
"${script_dir}/analyze_results.sh" "${script_dir}/results.csv" 1 \
    "$(awk -v seconds="${sample_seconds}" 'BEGIN { printf "%d", seconds * 1000 }')" \
    "${script_dir}/results_timing.csv" 3.0
