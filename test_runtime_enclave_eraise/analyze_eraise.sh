#!/bin/bash

# Script: extract_eraise.sh
# Usage: ./extract_eraise.sh [output_file]

# Configuration
OUTPUT_FILE="${1:-eraise.csv}"
PROGRAM="./main"

# Check if program exists
if [ ! -x "$PROGRAM" ]; then
    echo "Error: Program '$PROGRAM' not found or not executable"
    exit 1
fi

echo "=== Extract Eraise Timings to CSV ==="
echo "Program:      $PROGRAM"
echo "Output file:  $OUTPUT_FILE"
echo "Columns:      exception_delay,eraise_delay"
echo ""

# Create or update CSV file with header
create_csv_with_header() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "exception_delay,eraise_delay" > "$file"
        echo "Created: $file with header"
    else
        # Check if file has header
        if ! head -1 "$file" | grep -q "exception_delay,eraise_delay"; then
            # Backup original and add header
            cp "$file" "$file.bak"
            echo "exception_delay,eraise_delay" > "$file"
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
    echo "Error: Program produced no output"
    exit 1
fi

# ============================================================================
# Extract eraise timings
# ============================================================================
echo "=== Extracting Eraise Timings ==="

# Variables to store exception and eraise timings
declare -a EXCEPTION_TSCS
declare -a AEX_TSCS
declare -a ERAISE_TSCS
declare -a TIDS

EXCEPTION_COUNT=0
ENCLAVE_ENTRIES=0

echo "Looking for eraise timing patterns..."
echo "--------------------------------------"

# Process each line of output
CURRENT_TID=""
while IFS= read -r line; do
    # Match pattern: Enter enclave tid: X
    if [[ "$line" =~ Enter\ enclave\ tid:\ ([0-9]+) ]]; then
        CURRENT_TID="${BASH_REMATCH[1]}"
        ENCLAVE_ENTRIES=$((ENCLAVE_ENTRIES + 1))
        
    # Match pattern: exception_tsc: X, aex_tsc:Y, eraise_tsc:Z
    elif [[ "$line" =~ exception_tsc:\ ([0-9]+),\ aex_tsc:\ ([0-9]+),\ eraise_tsc:\ ([0-9]+) ]]; then
        exception_tsc="${BASH_REMATCH[1]}"
        aex_tsc="${BASH_REMATCH[2]}"
        eraise_tsc="${BASH_REMATCH[3]}"
        
        # Validate that timings are in expected order
        if (( aex_tsc >= exception_tsc && eraise_tsc >= aex_tsc )); then
            EXCEPTION_TSCS+=("$exception_tsc")
            AEX_TSCS+=("$aex_tsc")
            ERAISE_TSCS+=("$eraise_tsc")
            TIDS+=("$CURRENT_TID")
            EXCEPTION_COUNT=$((EXCEPTION_COUNT + 1))
            
            echo "  Found exception #$EXCEPTION_COUNT (TID:$CURRENT_TID):"
            echo "    exception_tsc: $exception_tsc"
            echo "    aex_tsc:       $aex_tsc"
            echo "    eraise_tsc:    $eraise_tsc"
            echo "    exception_delay: $((aex_tsc - exception_tsc)) cycles"
        else
            echo "  Warning: Unexpected timestamp order - skipping line"
            echo "    exception_tsc: $exception_tsc"
            echo "    aex_tsc:       $aex_tsc"
            echo "    eraise_tsc:    $eraise_tsc"
        fi
        CURRENT_TID=""
        
    # Match pattern: Exit enclave tid: X
    elif [[ "$line" =~ Exit\ enclave\ tid:\ ([0-9]+) ]]; then
        CURRENT_TID=""
    fi
done <<< "$OUTPUT"

echo "--------------------------------------"
echo "Total enclave entries: $ENCLAVE_ENTRIES"
echo "Total exception entries found: $EXCEPTION_COUNT"
echo ""

# ============================================================================
# Extract stage timings from LOG section
# ============================================================================
echo "=== Extracting Stage Timings from LOG ==="

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
    
    echo "Found in LOG section:"
    echo "  Stage 0 entries: $STAGE0_COUNT"
    echo "  Stage 1 entries: $STAGE1_COUNT"
else
    echo "Warning: Could not find LOG START and LOG END markers"
    echo "Will try to find stage timings in general output..."
    
    # Try to find stage timings in general output
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
    done <<< "$OUTPUT"
    
    echo "Found in general output:"
    echo "  Stage 0 entries: $STAGE0_COUNT"
    echo "  Stage 1 entries: $STAGE1_COUNT"
fi

echo ""

# ============================================================================
# Calculate eraise delays
# ============================================================================
echo "=== Calculating Eraise Delays ==="

declare -a EXCEPTION_DELAYS
declare -a ERAISE_DELAYS
declare -a MATCHED_STAGE1_TSCS

matched_count=0

for ((i=0; i<EXCEPTION_COUNT; i++)); do
    exception_tsc="${EXCEPTION_TSCS[$i]}"
    aex_tsc="${AEX_TSCS[$i]}"
    eraise_tsc="${ERAISE_TSCS[$i]}"
    tid="${TIDS[$i]}"
    
    # Calculate exception delay
    exception_delay=$((aex_tsc - exception_tsc))
    EXCEPTION_DELAYS+=("$exception_delay")
    
    # Find the smallest stage:1 timestamp that is greater than eraise_tsc
    eraise_delay="N/A"
    matched_stage1="N/A"
    min_diff=999999999999
    
    for stage1_tsc in "${STAGE1_TIMES[@]}"; do
        if (( stage1_tsc > eraise_tsc )); then
            diff=$((stage1_tsc - eraise_tsc))
            if (( diff < min_diff )); then
                min_diff=$diff
                eraise_delay=$diff
                matched_stage1="$stage1_tsc"
            fi
        fi
    done
    
    if [[ "$eraise_delay" != "N/A" ]]; then
        ERAISE_DELAYS+=("$eraise_delay")
        MATCHED_STAGE1_TSCS+=("$matched_stage1")
        matched_count=$((matched_count + 1))
        
        echo "  Exception #$((i+1)) (TID:$tid):"
        echo "    exception_tsc: $exception_tsc"
        echo "    aex_tsc:       $aex_tsc"
        echo "    eraise_tsc:    $eraise_tsc"
        echo "    matched stage1: $matched_stage1"
        echo "    exception_delay: $exception_delay cycles"
        echo "    eraise_delay:    $eraise_delay cycles"
    else
        ERAISE_DELAYS+=("N/A")
        MATCHED_STAGE1_TSCS+=("N/A")
        echo "  Exception #$((i+1)) (TID:$tid):"
        echo "    ERROR: Could not find stage:1 timestamp > $eraise_tsc"
        echo "    exception_delay: $exception_delay cycles"
        echo "    eraise_delay:    N/A"
    fi
done

echo ""
echo "Successfully calculated delays for $matched_count out of $EXCEPTION_COUNT exceptions"
echo ""

# ============================================================================
# Save to CSV
# ============================================================================
echo "=== Saving to CSV ==="

records_added=0
valid_records=0

for ((i=0; i<EXCEPTION_COUNT; i++)); do
    exception_delay="${EXCEPTION_DELAYS[$i]}"
    eraise_delay="${ERAISE_DELAYS[$i]}"
    
    if [[ "$eraise_delay" != "N/A" ]] && [[ "$exception_delay" != "N/A" ]]; then
        echo "$exception_delay,$eraise_delay" >> "$OUTPUT_FILE"
        records_added=$((records_added + 1))
        valid_records=$((valid_records + 1))
    else
        # Save with N/A if eraise_delay couldn't be calculated
        if [[ "$exception_delay" != "N/A" ]]; then
            echo "$exception_delay,N/A" >> "$OUTPUT_FILE"
            records_added=$((records_added + 1))
        fi
    fi
done

echo "Added $records_added records to $OUTPUT_FILE"
echo "  - Valid records (both delays): $valid_records"
echo "  - Partial records (only exception_delay): $((records_added - valid_records))"
echo ""

# ============================================================================
# Show summary
# ============================================================================
echo "=== Summary ==="
echo "Total exceptions found: $EXCEPTION_COUNT"
echo "Stage 1 entries found: $STAGE1_COUNT"
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

echo ""
echo "=== Raw Data Sample ==="
echo "First 5 exceptions with details:"
for ((i=0; i<5 && i<EXCEPTION_COUNT; i++)); do
    exception_tsc="${EXCEPTION_TSCS[$i]}"
    aex_tsc="${AEX_TSCS[$i]}"
    eraise_tsc="${ERAISE_TSCS[$i]}"
    matched_stage1="${MATCHED_STAGE1_TSCS[$i]}"
    exception_delay="${EXCEPTION_DELAYS[$i]}"
    eraise_delay="${ERAISE_DELAYS[$i]}"
    
    echo "  $((i+1)). TID:${TIDS[$i]}"
    echo "      exception_tsc: $exception_tsc"
    echo "      aex_tsc:       $aex_tsc"
    echo "      eraise_tsc:    $eraise_tsc"
    if [[ "$matched_stage1" != "N/A" ]]; then
        echo "      matched stage1: $matched_stage1"
    fi
    echo "      exception_delay: $exception_delay cycles"
    echo "      eraise_delay:    $eraise_delay cycles"
done

echo ""
echo "=== Stage 1 Timestamps (first 10) ==="
for ((i=0; i<10 && i<STAGE1_COUNT; i++)); do
    echo "  $((i+1)). ${STAGE1_TIMES[$i]}"
done

echo ""
echo "=== Done ==="