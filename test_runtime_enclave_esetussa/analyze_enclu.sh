#!/bin/bash

# Script: save_tsc_interval_simple.sh
# Usage: ./save_tsc_interval_simple.sh [output_csv_file]

# Configuration
PROGRAM="./main"

# Get output file from command line
if [[ -n "$1" ]]; then
    OUTPUT_FILE="$1"
else
    echo "Error: Please specify output CSV filename"
    echo "Usage: $0 output.csv"
    exit 1
fi

echo "=== TSC Interval Extractor ==="
echo "Program:      $PROGRAM"
echo "Output file:  $OUTPUT_FILE"
echo ""

# Create CSV file with header
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "interval" > "$OUTPUT_FILE"
    echo "Created: $OUTPUT_FILE with header"
else
    echo "Warning: $OUTPUT_FILE already exists, appending to it"
    if ! head -1 "$OUTPUT_FILE" | grep -q "^interval$"; then
        echo "Adding header..."
        cp "$OUTPUT_FILE" "$OUTPUT_FILE.bak"
        echo "interval" > "$OUTPUT_FILE"
        cat "$OUTPUT_FILE.bak" >> "$OUTPUT_FILE"
        rm "$OUTPUT_FILE.bak"
    fi
fi

echo ""

# Run program with taskset and capture output
echo "Running: taskset -c 0 $PROGRAM"
echo "------------------------------------------------------------"

OUTPUT=$(taskset -c 0 "$PROGRAM" 2>&1)
echo "$OUTPUT"
echo "------------------------------------------------------------"
echo ""

# Check if we got any output
if [ -z "$OUTPUT" ]; then
    echo "Warning: Program produced no output"
    echo "Appending N/A values to CSV file..."
    echo "N/A" >> "$OUTPUT_FILE"
    exit 0
fi

# ============================================================================
# Extract TSC Interval values
# ============================================================================
echo "=== Extracting TSC Intervals ==="

# Extract all TSC Interval values
declare -a TSC_INTERVALS
INTERVAL_COUNT=0

while IFS= read -r line; do
    # Match pattern: TSC Interval: 3960
    if [[ "$line" =~ TSC[[:space:]]*Interval:[[:space:]]*([0-9]+) ]]; then
        INTERVAL="${BASH_REMATCH[1]}"
        TSC_INTERVALS+=("$INTERVAL")
        INTERVAL_COUNT=$((INTERVAL_COUNT + 1))
        echo "Found TSC Interval: $INTERVAL"
    # Also try other possible patterns
    elif [[ "$line" =~ Interval:[[:space:]]*([0-9]+) ]] && [[ "$line" =~ TSC ]]; then
        INTERVAL="${BASH_REMATCH[1]}"
        TSC_INTERVALS+=("$INTERVAL")
        INTERVAL_COUNT=$((INTERVAL_COUNT + 1))
        echo "Found Interval (TSC mentioned): $INTERVAL"
    fi
done <<< "$OUTPUT"

echo ""
echo "Found $INTERVAL_COUNT TSC Interval values"
echo ""

# ============================================================================
# Save intervals to CSV
# ============================================================================
echo "=== Saving to CSV ==="

if [[ $INTERVAL_COUNT -eq 0 ]]; then
    echo "No TSC Interval values found in output"
    echo "Appending N/A to CSV..."
    echo "N/A" >> "$OUTPUT_FILE"
else
    for interval in "${TSC_INTERVALS[@]}"; do
        echo "$interval" >> "$OUTPUT_FILE"
    done
    echo "Saved $INTERVAL_COUNT intervals to $OUTPUT_FILE"
fi

# ============================================================================
# Statistics
# ============================================================================
echo ""
echo "=== Statistics ==="

if [[ ${#TSC_INTERVALS[@]} -gt 0 ]]; then
    # Calculate statistics
    min=${TSC_INTERVALS[0]}
    max=${TSC_INTERVALS[0]}
    sum=0
    
    for interval in "${TSC_INTERVALS[@]}"; do
        if (( interval < min )); then
            min=$interval
        fi
        if (( interval > max )); then
            max=$interval
        fi
        sum=$((sum + interval))
    done
    
    avg=$((sum / ${#TSC_INTERVALS[@]}))
    
    echo "TSC Interval Statistics:"
    echo "  Count:    ${#TSC_INTERVALS[@]}"
    echo "  Minimum:  $min cycles"
    echo "  Maximum:  $max cycles"
    echo "  Average:  $avg cycles"
    echo "  Total:    $sum cycles"
    
    # Calculate standard deviation if bc is available
    if command -v bc >/dev/null 2>&1; then
        sum_sq=0
        for interval in "${TSC_INTERVALS[@]}"; do
            diff=$((interval - avg))
            diff_sq=$((diff * diff))
            sum_sq=$((sum_sq + diff_sq))
        done
        variance=$((sum_sq / ${#TSC_INTERVALS[@]}))
        stddev=$(echo "scale=2; sqrt($variance)" | bc 2>/dev/null)
        echo "  Std Dev:  $stddev cycles"
    fi
    
    # Show all intervals
    echo ""
    echo "All TSC Intervals:"
    for ((i=0; i<${#TSC_INTERVALS[@]}; i++)); do
        printf "  %3d. %10d cycles\n" "$((i+1))" "${TSC_INTERVALS[$i]}"
    done
else
    echo "No TSC Interval values to analyze"
fi

# ============================================================================
# Final summary
# ============================================================================
echo ""
echo "=== Summary ==="
echo "Output saved to: $OUTPUT_FILE"
echo ""

echo "File content:"
echo "------------------------"
if [[ -s "$OUTPUT_FILE" ]]; then
    HEADER_LINE=$(head -1 "$OUTPUT_FILE")
    DATA_LINES=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
    
    echo "$HEADER_LINE"
    
    if [[ $DATA_LINES -le 10 ]]; then
        tail -n +2 "$OUTPUT_FILE"
    else
        echo "First 5 intervals:"
        tail -n +2 "$OUTPUT_FILE" | head -5
        echo "..."
        echo "Last 5 intervals:"
        tail -n +2 "$OUTPUT_FILE" | tail -5
    fi
else
    echo "(empty)"
fi
echo "------------------------"

echo ""
echo "=== Done ==="