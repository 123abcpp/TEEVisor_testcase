#!/bin/bash

# Script: analyze_eclone.sh
# Usage: ./analyze_eclone.sh [tcs_num] [output_csv_file]

# Configuration
PROGRAM="./main"

# Get TCS number from command line (first argument)
if [[ -n "$1" && "$1" =~ ^[0-9]+$ ]]; then
    TCS_NUM="$1"
    echo "Using TCS number: $TCS_NUM"
    shift  # Remove first argument so $2 becomes $1
else
    TCS_NUM="1"
    echo "Using default TCS number: $TCS_NUM"
fi

# Get output file from command line (now first argument after shift)
if [[ -n "$1" ]]; then
    OUTPUT_FILE="$1"
else
    OUTPUT_FILE="eclone.csv"
fi

echo "=== ECLONE Analyzer ==="
echo "Program:      $PROGRAM"
echo "TCS number:   $TCS_NUM"
echo "Output file:  $OUTPUT_FILE"
echo "Columns:      interval,metadata_page_num"
echo ""

# Create CSV file with header
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "interval,metadata_page_num" > "$OUTPUT_FILE"
    echo "Created: $OUTPUT_FILE with header"
else
    echo "Appending to existing file: $OUTPUT_FILE"
    if ! head -1 "$OUTPUT_FILE" | grep -q "^interval,metadata_page_num"; then
        echo "Adding header..."
        cp "$OUTPUT_FILE" "$OUTPUT_FILE.bak"
        echo "interval,metadata_page_num" > "$OUTPUT_FILE"
        cat "$OUTPUT_FILE.bak" >> "$OUTPUT_FILE"
        rm "$OUTPUT_FILE.bak"
    fi
fi

echo ""

# Run program with taskset and capture output
echo "Running: taskset -c 0 $PROGRAM $TCS_NUM"
echo "------------------------------------------------------------"

OUTPUT=$(taskset -c 0 "$PROGRAM" "$TCS_NUM" 2>&1)
echo "Program output captured (length: $(echo "$OUTPUT" | wc -l) lines)"
echo "------------------------------------------------------------"
echo ""

# Check if we got any output
if [ -z "$OUTPUT" ]; then
    echo "Error: Program produced no output"
    exit 1
fi

# ============================================================================
# Extract eclone_tsc and metadata_page_num
# ============================================================================
echo "=== Extracting ECLONE Timestamp and Metadata ==="

ECLONE_TSC=""
METADATA_PAGES="N/A"
TOTAL_PAGES="N/A"

echo "Looking for eclone_tsc and page numbers..."
echo "--------------------------------------"

while IFS= read -r line; do
    # Match pattern: eclone_tsc: X
    if [[ "$line" =~ eclone_tsc:\ ([0-9]+) ]]; then
        ECLONE_TSC="${BASH_REMATCH[1]}"
        echo "  Found eclone_tsc: $ECLONE_TSC"
    
    # Match pattern: total_page_num: 0xXXXX
    elif [[ "$line" =~ total_page_num:\ 0x([0-9a-fA-F]+) ]]; then
        TOTAL_PAGES=$((0x${BASH_REMATCH[1]}))
        echo "  Found total_page_num: $TOTAL_PAGES (0x${BASH_REMATCH[1]})"
    
    # Match pattern: metadata_page_num: 0xXXXX
    elif [[ "$line" =~ metadata_page_num:\ 0x([0-9a-fA-F]+) ]]; then
        METADATA_PAGES=$((0x${BASH_REMATCH[1]}))
        echo "  Found metadata_page_num: $METADATA_PAGES (0x${BASH_REMATCH[1]})"
    fi
done <<< "$OUTPUT"

echo "--------------------------------------"

if [[ -z "$ECLONE_TSC" ]]; then
    echo "Error: Could not find eclone_tsc in output"
    echo "Looking for any line with 'eclone_tsc':"
    echo "$OUTPUT" | grep -n "eclone_tsc"
    exit 1
fi

echo "Total pages: ${TOTAL_PAGES:-N/A}"
echo "Metadata pages: ${METADATA_PAGES:-N/A}"

# Check if metadata_page_num was found
if [[ "$METADATA_PAGES" == "N/A" ]]; then
    echo "Warning: metadata_page_num not found, using N/A"
fi

echo ""

# ============================================================================
# Extract stage timings from LOG section
# ============================================================================
echo "=== Extracting Stage Timings from LOG ==="

declare -a STAGE1_TIMES
STAGE1_COUNT=0

LOG_START_LINE=$(echo "$OUTPUT" | grep -n "=========LOG START=========" | cut -d: -f1)
LOG_END_LINE=$(echo "$OUTPUT" | grep -n "==========LOG END==========" | cut -d: -f1)

if [[ -n "$LOG_START_LINE" && -n "$LOG_END_LINE" ]]; then
    LOG_SECTION=$(echo "$OUTPUT" | sed -n "${LOG_START_LINE},${LOG_END_LINE}p")
    
    echo "Found LOG at lines $LOG_START_LINE to $LOG_END_LINE"
    
    # Extract stage1 timings only
    while IFS= read -r line; do
        if [[ "$line" =~ stage:\ 1,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
            TSC="${BASH_REMATCH[1]}"
            STAGE1_TIMES+=("$TSC")
            STAGE1_COUNT=$((STAGE1_COUNT + 1))
        fi
    done <<< "$LOG_SECTION"
    
    echo "Found $STAGE1_COUNT stage 1 entries in LOG section"
    
    if [[ $STAGE1_COUNT -gt 0 ]]; then
        echo ""
        echo "Stage 1 timestamps (first 5):"
        for ((i=0; i<STAGE1_COUNT && i<5; i++)); do
            echo "  $((i+1)). ${STAGE1_TIMES[$i]}"
        done
        if [[ $STAGE1_COUNT -gt 5 ]]; then
            echo "  ... and $((STAGE1_COUNT - 5)) more"
        fi
    fi
else
    echo "Warning: Could not find LOG START and LOG END markers"
    echo "Will try to find stage timings in general output..."
    
    # Try to find stage timings in general output
    while IFS= read -r line; do
        if [[ "$line" =~ stage:\ 1,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
            TSC="${BASH_REMATCH[1]}"
            STAGE1_TIMES+=("$TSC")
            STAGE1_COUNT=$((STAGE1_COUNT + 1))
        fi
    done <<< "$OUTPUT"
    
    echo "Found $STAGE1_COUNT stage 1 entries in general output"
fi

echo ""

# ============================================================================
# Calculate eclone interval
# ============================================================================
echo "=== Calculating ECLONE Interval ==="

if [[ $STAGE1_COUNT -eq 0 ]]; then
    echo "Error: No stage 1 timestamps found"
    INTERVAL="N/A"
else
    # Find the smallest stage:1 timestamp that is greater than eclone_tsc
    INTERVAL="N/A"
    MIN_DIFF=999999999999
    
    echo "Looking for stage1 timestamp > eclone_tsc ($ECLONE_TSC)..."
    echo "------------------------------------------------------------"
    
    for ((i=0; i<STAGE1_COUNT; i++)); do
        STAGE1_TSC="${STAGE1_TIMES[$i]}"
        
        if (( STAGE1_TSC > ECLONE_TSC )); then
            DIFF=$((STAGE1_TSC - ECLONE_TSC))
            echo "  Stage1[$i]: $STAGE1_TSC (diff: $DIFF cycles)"
            
            if (( DIFF < MIN_DIFF )); then
                MIN_DIFF=$DIFF
                INTERVAL=$DIFF
            fi
        else
            echo "  Stage1[$i]: $STAGE1_TSC (before eclone_tsc, skipping)"
        fi
    done
    
    echo "------------------------------------------------------------"
    
    if [[ "$INTERVAL" == "N/A" ]]; then
        echo "Warning: Could not find any stage1 timestamp > $ECLONE_TSC"
        
        # Find the closest stage1 timestamp (after eclone_tsc)
        echo "Looking for closest stage1 timestamp after eclone_tsc..."
        CLOSEST_DIFF=999999999999
        
        for ((i=0; i<STAGE1_COUNT; i++)); do
            STAGE1_TSC="${STAGE1_TIMES[$i]}"
            if (( STAGE1_TSC > ECLONE_TSC )); then
                DIFF=$((STAGE1_TSC - ECLONE_TSC))
                if (( DIFF < CLOSEST_DIFF )); then
                    CLOSEST_DIFF=$DIFF
                    INTERVAL=$DIFF
                fi
            fi
        done
        
        if [[ "$INTERVAL" != "N/A" ]]; then
            echo "Found stage1 after eclone_tsc with diff: $INTERVAL cycles"
        else
            echo "No stage1 timestamps found after eclone_tsc"
        fi
    else
        echo "✓ Found matching stage1 with interval: $INTERVAL cycles"
    fi
fi

echo ""

# ============================================================================
# Save results to CSV
# ============================================================================
echo "=== Saving Results to CSV ==="

# Ensure metadata_pages is a number or N/A
if [[ "$METADATA_PAGES" == "N/A" ]]; then
    METADATA_VALUE="N/A"
else
    METADATA_VALUE="$METADATA_PAGES"
fi

# Save interval and metadata_page_num to CSV
if [[ "$INTERVAL" == "N/A" ]]; then
    echo "N/A,$METADATA_VALUE" >> "$OUTPUT_FILE"
    echo "Saved to $OUTPUT_FILE: interval=N/A, metadata_page_num=$METADATA_VALUE"
else
    echo "$INTERVAL,$METADATA_VALUE" >> "$OUTPUT_FILE"
    echo "Saved to $OUTPUT_FILE: interval=$INTERVAL, metadata_page_num=$METADATA_VALUE"
fi

# ============================================================================
# Additional information
# ============================================================================
echo ""
echo "=== Additional Information ==="

if [[ "$INTERVAL" != "N/A" && "$INTERVAL" =~ ^[0-9]+$ ]]; then
    # Convert cycles to microseconds (assuming 2.5GHz CPU)
    CPU_FREQ_GHZ=2.5
    MICROSECONDS=$(echo "scale=3; $INTERVAL / ($CPU_FREQ_GHZ * 1000)" | bc 2>/dev/null || echo "N/A")
    
    echo "Interval analysis:"
    echo "  Cycles: $INTERVAL"
    if [[ "$MICROSECONDS" != "N/A" ]]; then
        echo "  Time:   $MICROSECONDS μs (at ${CPU_FREQ_GHZ}GHz)"
    fi
fi

if [[ "$TOTAL_PAGES" != "N/A" && "$METADATA_PAGES" != "N/A" ]]; then
    echo ""
    echo "Page analysis:"
    echo "  Total pages:    $TOTAL_PAGES"
    echo "  Metadata pages: $METADATA_PAGES"
    echo "  Data pages:     $((TOTAL_PAGES - METADATA_PAGES))"
    
    if [[ "$INTERVAL" != "N/A" && "$INTERVAL" =~ ^[0-9]+$ && $METADATA_PAGES -gt 0 ]]; then
        # Calculate per-metadata-page time (rough estimate)
        PER_PAGE_TIME=$((INTERVAL / METADATA_PAGES))
        echo "  Per metadata page: ~$PER_PAGE_TIME cycles"
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=== Summary ==="
echo "ECLONE Analysis Complete!"
echo ""
echo "Results saved to: $OUTPUT_FILE"

# Show recent entries
echo ""
echo "Recent entries in CSV:"
echo "------------------------"
echo "interval,metadata_page_num"
tail -5 "$OUTPUT_FILE" | while IFS= read -r line; do
    echo "$line"
done
echo "------------------------"

echo ""
echo "=== Done ==="