#!/bin/bash

# Script: save_eaug_intervals.sh
# Usage: ./save_eaug_intervals.sh [output_file]

# Configuration
OUTPUT_FILE="${1:-eaug.csv}"
PROGRAM="./main"

# Check if program exists
if [ ! -x "$PROGRAM" ]; then
    echo "Error: Program '$PROGRAM' not found or not executable"
    exit 1
fi

echo "=== EAUG Intervals Extractor ==="
echo "Program:      $PROGRAM"
echo "Output file:  $OUTPUT_FILE"
echo "Column:       interval"
echo ""

# Create or update CSV file with header
create_csv_with_header() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "interval" > "$file"
        echo "Created: $file with header"
    else
        # Check if file has header
        if ! head -1 "$file" | grep -q "^interval$"; then
            # Backup original and add header
            cp "$file" "$file.bak"
            echo "interval" > "$file"
            cat "$file.bak" >> "$file"
            rm "$file.bak"
            echo "Added header to existing file: $file"
        else
            echo "Appending to existing file: $file"
        fi
    fi
}

create_csv_with_header "$OUTPUT_FILE"

echo ""

# Run program with taskset and capture output
echo "Running: taskset -c 0 $PROGRAM"
echo "------------------------------------------------------------"

# Run the program and capture output
OUTPUT=$(taskset -c 0 "$PROGRAM" 2>&1)
echo "Program output captured"
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
# Extract EAUG data from LOG section
# ============================================================================
echo "=== Extracting EAUG Data ==="

# Find LOG START and LOG END
LOG_START_LINE=$(echo "$OUTPUT" | grep -n "=========LOG START=========" | cut -d: -f1)
LOG_END_LINE=$(echo "$OUTPUT" | grep -n "==========LOG END==========" | cut -d: -f1)

if [[ -z "$LOG_START_LINE" || -z "$LOG_END_LINE" ]]; then
    echo "Error: Could not find LOG START and LOG END markers"
    exit 1
fi

echo "Found LOG section at lines $LOG_START_LINE to $LOG_END_LINE"
echo ""

# Extract LOG section
LOG_SECTION=$(echo "$OUTPUT" | sed -n "${LOG_START_LINE},${LOG_END_LINE}p")

echo "LOG section content:"
echo "$LOG_SECTION"
echo ""

# Extract stage 0 and stage 1 data
declare -a STAGE0_TIMES
declare -a STAGE1_TIMES
STAGE0_COUNT=0
STAGE1_COUNT=0

while IFS= read -r line; do
    if [[ "$line" =~ stage:\ 0,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
        TSC="${BASH_REMATCH[1]}"
        STAGE0_TIMES+=("$TSC")
        STAGE0_COUNT=$((STAGE0_COUNT + 1))
    elif [[ "$line" =~ stage:\ 1,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
        TSC="${BASH_REMATCH[1]}"
        STAGE1_TIMES+=("$TSC")
        STAGE1_COUNT=$((STAGE1_COUNT + 1))
    fi
done <<< "$LOG_SECTION"

echo "Found in LOG section:"
echo "  - Stage 0 entries: $STAGE0_COUNT"
echo "  - Stage 1 entries: $STAGE1_COUNT"
echo ""

# ============================================================================
# Match intervals for EAUG
# ============================================================================
echo "=== Matching EAUG Intervals ==="

if [[ $STAGE0_COUNT -eq 0 || $STAGE1_COUNT -eq 0 ]]; then
    echo "Error: No stage 0 or stage 1 entries found in LOG section"
    exit 1
fi

# For EAUG, we expect exactly one pair or multiple sequential pairs
if [[ $STAGE0_COUNT -eq $STAGE1_COUNT ]]; then
    echo "Found $STAGE0_COUNT stage 0 -> stage 1 pairs"
    echo ""
    
    # Simple pairing: assume they come in order
    for ((i=0; i<STAGE0_COUNT; i++)); do
        if [[ -n "${STAGE0_TIMES[$i]}" && -n "${STAGE1_TIMES[$i]}" ]]; then
            interval=$((STAGE1_TIMES[$i] - STAGE0_TIMES[$i]))
            
            if (( interval >= 0 )); then
                echo "Pair $((i+1)): ${STAGE0_TIMES[$i]} -> ${STAGE1_TIMES[$i]} = $interval cycles"
                echo "$interval" >> "$OUTPUT_FILE"
            else
                echo "Warning: Negative interval at pair $((i+1)): $interval"
            fi
        fi
    done
else
    echo "Warning: Stage count mismatch ($STAGE0_COUNT stage 0 vs $STAGE1_COUNT stage 1)"
    echo "Using sequential matching..."
    
    # Try to match each stage 0 with the next stage 1
    matched_pairs=0
    current_stage1_idx=0
    
    for ((i=0; i<STAGE0_COUNT; i++)); do
        stage0_tsc="${STAGE0_TIMES[$i]}"
        
        # Find next stage 1
        for ((j=current_stage1_idx; j<STAGE1_COUNT; j++)); do
            stage1_tsc="${STAGE1_TIMES[$j]}"
            
            if (( stage1_tsc > stage0_tsc )); then
                interval=$((stage1_tsc - stage0_tsc))
                
                echo "Matched: ${STAGE0_TIMES[$i]} -> ${STAGE1_TIMES[$j]} = $interval cycles"
                echo "$interval" >> "$OUTPUT_FILE"
                
                matched_pairs=$((matched_pairs + 1))
                current_stage1_idx=$((j + 1))
                break
            fi
        done
    done
    
    echo ""
    echo "Matched $matched_pairs pairs"
fi

# ============================================================================
# Statistics
# ============================================================================
echo ""
echo "=== EAUG Statistics ==="

# Count records in CSV (excluding header)
record_count=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "Total EAUG intervals saved: $record_count"

if [[ $record_count -gt 0 ]]; then
    # Calculate statistics
    declare -a INTERVALS
    
    while IFS= read -r interval; do
        if [[ "$interval" =~ ^[0-9]+$ ]] && [[ "$interval" != "N/A" ]]; then
            INTERVALS+=("$interval")
        fi
    done < <(tail -n +2 "$OUTPUT_FILE")
    
    if [[ ${#INTERVALS[@]} -gt 0 ]]; then
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
        
        echo "Statistics (${#INTERVALS[@]} valid intervals):"
        echo "  Minimum:   $min cycles"
        echo "  Maximum:   $max cycles"
        echo "  Average:   $avg cycles"
        echo "  Total:     $sum cycles"
        
        # Show all intervals
        echo ""
        echo "All EAUG intervals:"
        for ((i=0; i<${#INTERVALS[@]}; i++)); do
            printf "  %3d. %10d cycles\n" "$((i+1))" "${INTERVALS[$i]}"
        done
    else
        echo "No valid intervals found in CSV"
    fi
fi

# ============================================================================
# Show CSV content
# ============================================================================
echo ""
echo "=== CSV File Content ==="
echo "File: $OUTPUT_FILE"
echo "------------------------"
cat "$OUTPUT_FILE"
echo "------------------------"

echo ""
echo "=== Done ==="