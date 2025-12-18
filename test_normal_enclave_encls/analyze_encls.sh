#!/bin/bash

# Script: save_interval_simple.sh
# Usage: ./save_interval_simple.sh [output_csv_file]

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

echo "=== Simple Interval Extractor ==="
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
# Extract LOG section
# ============================================================================
echo "=== Extracting LOG Section ==="

# Find LOG START and LOG END
LOG_START=$(echo "$OUTPUT" | grep -n "=========LOG START=========" | head -1 | cut -d: -f1)
LOG_END=$(echo "$OUTPUT" | grep -n "==========LOG END==========" | head -1 | cut -d: -f1)

if [[ -z "$LOG_START" || -z "$LOG_END" ]]; then
    echo "Error: Could not find LOG START and LOG END markers"
    exit 1
fi

echo "Found LOG at lines $LOG_START to $LOG_END"
echo ""

# Extract LOG content
LOG_CONTENT=$(echo "$OUTPUT" | sed -n "${LOG_START},${LOG_END}p")

echo "LOG content:"
echo "$LOG_CONTENT"
echo ""

# ============================================================================
# Extract and match intervals
# ============================================================================
echo "=== Extracting Intervals ==="

# Extract stage 0 and stage 1 times
declare -a STAGE0_TIMES
declare -a STAGE1_TIMES

while IFS= read -r line; do
    if [[ "$line" =~ stage:\ 0,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
        STAGE0_TIMES+=("${BASH_REMATCH[1]}")
    elif [[ "$line" =~ stage:\ 1,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
        STAGE1_TIMES+=("${BASH_REMATCH[1]}")
    fi
done <<< "$LOG_CONTENT"

echo "Found ${#STAGE0_TIMES[@]} stage 0 entries"
echo "Found ${#STAGE1_TIMES[@]} stage 1 entries"
echo ""

# Match intervals
INTERVAL_COUNT=0

if [[ ${#STAGE0_TIMES[@]} -eq ${#STAGE1_TIMES[@]} ]] && [[ ${#STAGE0_TIMES[@]} -gt 0 ]]; then
    # Exact match (same number of stage0 and stage1)
    echo "Matching ${#STAGE0_TIMES[@]} pairs:"
    
    for ((i=0; i<${#STAGE0_TIMES[@]}; i++)); do
        interval=$((STAGE1_TIMES[i] - STAGE0_TIMES[i]))
        
        if (( interval >= 0 )); then
            echo "  $((i+1)). ${STAGE0_TIMES[i]} -> ${STAGE1_TIMES[i]} = $interval cycles"
            echo "$interval" >> "$OUTPUT_FILE"
            INTERVAL_COUNT=$((INTERVAL_COUNT + 1))
        else
            echo "  Warning: Negative interval at pair $((i+1)): $interval"
        fi
    done
else
    # Sequential matching
    echo "Stage count mismatch, using sequential matching:"
    
    matched=0
    current_idx=0
    
    for ((i=0; i<${#STAGE0_TIMES[@]}; i++)); do
        stage0_tsc="${STAGE0_TIMES[$i]}"
        
        for ((j=current_idx; j<${#STAGE1_TIMES[@]}; j++)); do
            stage1_tsc="${STAGE1_TIMES[$j]}"
            
            if (( stage1_tsc > stage0_tsc )); then
                interval=$((stage1_tsc - stage0_tsc))
                echo "  $((matched+1)). $stage0_tsc -> $stage1_tsc = $interval cycles"
                echo "$interval" >> "$OUTPUT_FILE"
                
                INTERVAL_COUNT=$((INTERVAL_COUNT + 1))
                matched=$((matched + 1))
                current_idx=$((j + 1))
                break
            fi
        done
    done
    
    echo "  Matched $matched intervals"
fi

# ============================================================================
# Statistics
# ============================================================================
echo ""
echo "=== Statistics ==="
echo "Total intervals saved: $INTERVAL_COUNT"
echo ""

if [[ $INTERVAL_COUNT -gt 0 ]]; then
    # Read intervals back from CSV for statistics
    declare -a INTERVALS
    
    while IFS= read -r interval; do
        if [[ "$interval" =~ ^[0-9]+$ ]] && [[ "$interval" != "N/A" ]]; then
            INTERVALS+=("$interval")
        fi
    done < <(tail -n +2 "$OUTPUT_FILE")
    
    if [[ ${#INTERVALS[@]} -gt 0 ]]; then
        # Calculate statistics
        min=${INTERVALS[0]}
        max=${INTERVALS[0]}
        sum=0
        
        for interval in "${INTERVALS[@]}"; do
            if (( interval < min )); then
                min=$interval
            fi
            if (( interval > max )); then
                max=$interval
            fi
            sum=$((sum + interval))
        done
        
        avg=$((sum / ${#INTERVALS[@]}))
        
        echo "Interval Statistics:"
        echo "  Count:    ${#INTERVALS[@]}"
        echo "  Minimum:  $min cycles"
        echo "  Maximum:  $max cycles"
        echo "  Average:  $avg cycles"
        echo "  Total:    $sum cycles"
        
        # Show all intervals
        echo ""
        echo "All intervals:"
        for ((i=0; i<${#INTERVALS[@]}; i++)); do
            printf "  %3d. %10d cycles\n" "$((i+1))" "${INTERVALS[$i]}"
        done
    fi
fi

# ============================================================================
# Final summary
# ============================================================================
echo ""
echo "=== Summary ==="
echo "Output saved to: $OUTPUT_FILE"
echo "File content:"
echo "------------------------"
cat "$OUTPUT_FILE"
echo "------------------------"

echo ""
echo "=== Done ==="