#!/bin/bash

# Script: save_intervals_with_measure.sh
# Usage: ./save_intervals_with_measure.sh [output_file]

# Configuration
OUTPUT_FILE="${1:-eaddb.csv}"
PROGRAM="./main"

# Check if program exists
if [ ! -x "$PROGRAM" ]; then
    echo "Error: Program '$PROGRAM' not found or not executable"
    exit 1
fi

echo "=== Save Intervals to CSV (with measure flag) ==="
echo "Program:      $PROGRAM"
echo "Output file:  $OUTPUT_FILE"
echo "Columns:      interval,num,measure"
echo ""

# Create or update CSV file with header
create_csv_with_header() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "interval,num,measure" > "$file"
        echo "Created: $file with header"
    else
        # Check if file has header
        if ! head -1 "$file" | grep -q "interval,num,measure"; then
            # Backup original and add header
            cp "$file" "$file.bak"
            echo "interval,num,measure" > "$file"
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
echo "Program output captured (truncated for display)"
echo "------------------------------------------------------------"
echo ""

# Check if we got any output
if [ -z "$OUTPUT" ]; then
    echo "Warning: Program produced no output"
    echo "Appending N/A values to CSV file..."
    echo "N/A,N/A,N/A" >> "$OUTPUT_FILE"
    exit 0
fi

# ============================================================================
# Extract data
# ============================================================================
echo "=== Extracting Data ==="

# Extract page numbers with measure flag
declare -a PAGE_NUMBERS
declare -a MEASURE_FLAGS
PAGE_COUNT=0

echo "Parsing page operations with measure flags:"
echo "------------------------------------------"

while IFS= read -r line; do
    # Match pattern: add page number: X, measure: Y
    if [[ "$line" =~ add\ page\ number:\ ([0-9]+),\ measure:\ ([01]) ]]; then
        PAGES="${BASH_REMATCH[1]}"
        MEASURE="${BASH_REMATCH[2]}"
        PAGE_NUMBERS+=("$PAGES")
        MEASURE_FLAGS+=("$MEASURE")
        
        echo "  Found: $PAGES pages, measure=$MEASURE"
        PAGE_COUNT=$((PAGE_COUNT + 1))
    # Also check for pattern without measure (backward compatibility)
    elif [[ "$line" =~ add\ page\ number:\ ([0-9]+)$ ]] || [[ "$line" =~ add\ page\ number:\ ([0-9]+)\ *$ ]]; then
        PAGES="${BASH_REMATCH[1]}"
        PAGE_NUMBERS+=("$PAGES")
        MEASURE_FLAGS+=("1")  # Default to measure=1 for backward compatibility
        echo "  Found: $PAGES pages, measure=1 (default)"
        PAGE_COUNT=$((PAGE_COUNT + 1))
    fi
done <<< "$OUTPUT"

echo "------------------------------------------"
echo "Total page operations found: $PAGE_COUNT"
echo ""

# Extract stage 0 and stage 1 data from LOG section
declare -a STAGE0_TIMES
declare -a STAGE1_TIMES
STAGE0_COUNT=0
STAGE1_COUNT=0

LOG_START_LINE=$(echo "$OUTPUT" | grep -n "=========LOG START=========" | cut -d: -f1)
LOG_END_LINE=$(echo "$OUTPUT" | grep -n "==========LOG END==========" | cut -d: -f1)

if [[ -n "$LOG_START_LINE" && -n "$LOG_END_LINE" ]]; then
    LOG_SECTION=$(echo "$OUTPUT" | sed -n "${LOG_START_LINE},${LOG_END_LINE}p")
    
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
else
    echo "Error: Could not find LOG START and LOG END markers"
    exit 1
fi

echo "Found $STAGE0_COUNT stage 0 entries and $STAGE1_COUNT stage 1 entries in log"
echo ""

# ============================================================================
# Match intervals
# ============================================================================
echo "=== Matching Intervals ==="

matched_pairs=0
current_stage1_idx=0
declare -a INTERVALS

for ((i=0; i<STAGE0_COUNT; i++)); do
    stage0_tsc="${STAGE0_TIMES[$i]}"
    
    # Find next stage 1
    for ((j=current_stage1_idx; j<STAGE1_COUNT; j++)); do
        stage1_tsc="${STAGE1_TIMES[$j]}"
        
        if (( stage1_tsc > stage0_tsc )); then
            interval=$((stage1_tsc - stage0_tsc))
            INTERVALS+=("$interval")
            matched_pairs=$((matched_pairs + 1))
            current_stage1_idx=$((j + 1))
            break
        fi
    done
done

echo "Matched $matched_pairs intervals"
echo ""

# ============================================================================
# Process page numbers and save to CSV
# ============================================================================
echo "=== Processing and Saving to CSV ==="

interval_idx=0
page_idx=0
records_added=0
measure_1_count=0
measure_0_count=0

# Process each page number with its measure flag
for ((p=0; p<PAGE_COUNT && interval_idx<matched_pairs; p++)); do
    pages=${PAGE_NUMBERS[$p]}
    measure=${MEASURE_FLAGS[$p]}
    
    if [[ $pages -le 127 ]]; then
        # Single interval for pages <= 127
        if [[ $interval_idx -lt $matched_pairs ]]; then
            interval=${INTERVALS[$interval_idx]}
            
            # Save to CSV (without average column)
            echo "$interval,$pages,$measure" >> "$OUTPUT_FILE"
            records_added=$((records_added + 1))
            
            # Count by measure type
            if [[ $measure -eq 1 ]]; then
                measure_1_count=$((measure_1_count + 1))
            else
                measure_0_count=$((measure_0_count + 1))
            fi
            
            interval_idx=$((interval_idx + 1))
        fi
    else
        # Multiple intervals for pages > 127
        full_sets=$((pages / 127))
        remainder=$((pages % 127))
        
        # Process full 127-page sets
        for ((s=0; s<full_sets && interval_idx<matched_pairs; s++)); do
            interval=${INTERVALS[$interval_idx]}
            
            echo "$interval,127,$measure" >> "$OUTPUT_FILE"
            records_added=$((records_added + 1))
            
            # Count by measure type
            if [[ $measure -eq 1 ]]; then
                measure_1_count=$((measure_1_count + 1))
            else
                measure_0_count=$((measure_0_count + 1))
            fi
            
            interval_idx=$((interval_idx + 1))
        done
        
        # Process remainder
        if [[ $remainder -gt 0 && $interval_idx -lt $matched_pairs ]]; then
            interval=${INTERVALS[$interval_idx]}
            
            echo "$interval,$remainder,$measure" >> "$OUTPUT_FILE"
            records_added=$((records_added + 1))
            
            # Count by measure type
            if [[ $measure -eq 1 ]]; then
                measure_1_count=$((measure_1_count + 1))
            else
                measure_0_count=$((measure_0_count + 1))
            fi
            
            interval_idx=$((interval_idx + 1))
        fi
    fi
done

# If there are remaining intervals not matched to page numbers
if [[ $interval_idx -lt $matched_pairs ]]; then
    remaining=$((matched_pairs - interval_idx))
    echo "Note: $remaining intervals not matched to page operations"
    echo "Saving them with num=0, measure=1"
    
    for ((i=interval_idx; i<matched_pairs; i++)); do
        interval=${INTERVALS[$i]}
        echo "$interval,0,1" >> "$OUTPUT_FILE"  # When num=0, measure=1
        records_added=$((records_added + 1))
        measure_1_count=$((measure_1_count + 1))
    done
fi

echo "Added $records_added records to CSV"
echo "  - With measure=1: $measure_1_count records"
echo "  - With measure=0: $measure_0_count records"
echo ""

# ============================================================================
# Show summary
# ============================================================================
echo "=== Summary ==="
echo "Page operations processed: $PAGE_COUNT"
echo "Total intervals found: $matched_pairs"
echo "Records saved to CSV: $records_added"
echo "Output file: $OUTPUT_FILE"
echo ""

echo "=== CSV Preview ==="
echo "First 10 lines of $OUTPUT_FILE:"
echo "--------------------------------"
head -11 "$OUTPUT_FILE" | while IFS= read -r line; do
    echo "$line"
done

echo ""
echo "Last 10 lines of $OUTPUT_FILE:"
echo "-------------------------------"
tail -11 "$OUTPUT_FILE" | while IFS= read -r line; do
    echo "$line"
done

# ============================================================================
# Statistics separated by measure flag
# ============================================================================
echo ""
echo "=== Statistics by Measure Flag ==="

# Function to calculate statistics for a specific measure value
calculate_stats() {
    local measure_value="$1"
    local description="$2"
    
    local sum_interval=0
    local sum_num=0
    local count=0
    
    while IFS=',' read -r interval num measure; do
        if [[ "$interval" =~ ^[0-9]+$ ]] && [[ "$interval" != "N/A" ]] && [[ "$measure" == "$measure_value" ]]; then
            sum_interval=$((sum_interval + interval))
            sum_num=$((sum_num + num))
            count=$((count + 1))
        fi
    done < <(tail -n +2 "$OUTPUT_FILE")
    
    if [[ $count -gt 0 ]]; then
        local avg_interval=$((sum_interval / count))
        local avg_num=$((sum_num / count))
        
        echo "$description ($count records):"
        echo "  Average interval: $avg_interval cycles"
        echo "  Average num:      $avg_num pages"
        echo ""
    else
        echo "$description: No records found"
        echo ""
    fi
}

# Calculate statistics for measure=1 and measure=0 separately
calculate_stats "1" "Measure=1 (measured operations)"
calculate_stats "0" "Measure=0 (unmeasured operations)"

# Overall statistics
echo "=== Overall Statistics ==="
total_records=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
if [[ $total_records -gt 0 ]]; then
    sum_interval=0
    sum_num=0
    count=0
    
    while IFS=',' read -r interval num measure; do
        if [[ "$interval" =~ ^[0-9]+$ ]] && [[ "$interval" != "N/A" ]]; then
            sum_interval=$((sum_interval + interval))
            sum_num=$((sum_num + num))
            count=$((count + 1))
        fi
    done < <(tail -n +2 "$OUTPUT_FILE")
    
    if [[ $count -gt 0 ]]; then
        avg_interval=$((sum_interval / count))
        avg_num=$((sum_num / count))
        
        echo "All records ($count total):"
        echo "  Average interval: $avg_interval cycles"
        echo "  Average num:      $avg_num pages"
    fi
fi

echo ""
echo "=== Detailed Breakdown ==="

# Additional breakdown by page size
echo "By page size (measure=1 only):"
echo "Pages  Records  Avg Interval"
echo "----------------------------"

# Check 127-page operations
count_127=0
sum_interval_127=0
while IFS=',' read -r interval num measure; do
    if [[ "$num" == "127" ]] && [[ "$measure" == "1" ]]; then
        count_127=$((count_127 + 1))
        sum_interval_127=$((sum_interval_127 + interval))
    fi
done < <(tail -n +2 "$OUTPUT_FILE")

if [[ $count_127 -gt 0 ]]; then
    avg_interval_127=$((sum_interval_127 / count_127))
    printf " 127   %7d  %13d\n" "$count_127" "$avg_interval_127"
fi

# Check 1-page operations
count_1=0
sum_interval_1=0
while IFS=',' read -r interval num measure; do
    if [[ "$num" == "1" ]] && [[ "$measure" == "1" ]]; then
        count_1=$((count_1 + 1))
        sum_interval_1=$((sum_interval_1 + interval))
    fi
done < <(tail -n +2 "$OUTPUT_FILE")

if [[ $count_1 -gt 0 ]]; then
    avg_interval_1=$((sum_interval_1 / count_1))
    printf "   1   %7d  %13d\n" "$count_1" "$avg_interval_1"
fi

echo ""
echo "=== Done ==="