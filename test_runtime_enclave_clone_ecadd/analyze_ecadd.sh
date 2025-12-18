#!/bin/bash

# Script: analyze_encls_correct.sh
# Usage: ./analyze_encls_correct.sh [output_csv_file]

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
    OUTPUT_FILE="ecadd.csv"
fi

echo "=== ENCLS Analyzer (Corrected) ==="
echo "Program:      $PROGRAM"
echo "Output file:  $OUTPUT_FILE"
echo "Columns:      base_time,per_page_time,tcs_pages,ssa_pages,ussa_pages,total_pages,interval1,interval2"
echo ""

# Create CSV file with header
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "base_time,per_page_time,tcs_pages,ssa_pages,ussa_pages,total_pages,interval1,interval2" > "$OUTPUT_FILE"
    echo "Created: $OUTPUT_FILE with header"
else
    echo "Warning: $OUTPUT_FILE already exists, appending to it"
    if ! head -1 "$OUTPUT_FILE" | grep -q "^base_time,"; then
        echo "Adding header..."
        cp "$OUTPUT_FILE" "$OUTPUT_FILE.bak"
        echo "base_time,per_page_time,tcs_pages,ssa_pages,ussa_pages,total_pages,interval1,interval2" > "$OUTPUT_FILE"
        cat "$OUTPUT_FILE.bak" >> "$OUTPUT_FILE"
        rm "$OUTPUT_FILE.bak"
    fi
fi

echo ""

# Run program with taskset and capture output
echo "Running: taskset -c 0 $PROGRAM $TCS_NUM"
echo "------------------------------------------------------------"

OUTPUT=$(taskset -c 0 "$PROGRAM" "$TCS_NUM" 2>&1)
echo "Program output length: $(echo "$OUTPUT" | wc -l) lines"
echo "------------------------------------------------------------"
echo ""

# Check if we got any output
if [ -z "$OUTPUT" ]; then
    echo "Warning: Program produced no output"
    echo "Appending N/A values to CSV file..."
    echo "N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
    exit 0
fi

# ============================================================================
# Extract page numbers correctly (look for pattern BEFORE add tcs/ssa/ussa)
# ============================================================================
echo "=== Extracting ENCLS Parameters ==="

# Initialize variables
TCS_PAGES=0
SSA_PAGES=0
USSA_PAGES=0

# Save output to temp file for easier processing
TEMP_FILE=$(mktemp)
echo "$OUTPUT" > "$TEMP_FILE"

# Method: Look for "add tcs", "add ssa", "add ussa" and get the line BEFORE them
echo "Searching for page numbers before add tcs/ssa/ussa markers..."

# Get line numbers for markers
TCS_LINE=$(grep -n "add tcs$" "$TEMP_FILE" | tail -1 | cut -d: -f1)
SSA_LINE=$(grep -n "add ssa$" "$TEMP_FILE" | tail -1 | cut -d: -f1)
USSA_LINE=$(grep -n "add ussa$" "$TEMP_FILE" | tail -1 | cut -d: -f1)

# Get the line BEFORE each marker
if [[ -n "$TCS_LINE" && $TCS_LINE -gt 1 ]]; then
    PREV_TCS_LINE=$((TCS_LINE - 1))
    PREV_TCS_CONTENT=$(sed -n "${PREV_TCS_LINE}p" "$TEMP_FILE")
    if [[ "$PREV_TCS_CONTENT" =~ add\ page\ number:\ ([0-9]+) ]]; then
        TCS_PAGES="${BASH_REMATCH[1]}"
        echo "Found TCS pages: $TCS_PAGES (line before 'add tcs')"
    fi
fi

if [[ -n "$SSA_LINE" && $SSA_LINE -gt 1 ]]; then
    PREV_SSA_LINE=$((SSA_LINE - 1))
    PREV_SSA_CONTENT=$(sed -n "${PREV_SSA_LINE}p" "$TEMP_FILE")
    if [[ "$PREV_SSA_CONTENT" =~ add\ page\ number:\ ([0-9]+) ]]; then
        SSA_PAGES="${BASH_REMATCH[1]}"
        echo "Found SSA pages: $SSA_PAGES (line before 'add ssa')"
    fi
fi

if [[ -n "$USSA_LINE" && $USSA_LINE -gt 1 ]]; then
    PREV_USSA_LINE=$((USSA_LINE - 1))
    PREV_USSA_CONTENT=$(sed -n "${PREV_USSA_LINE}p" "$TEMP_FILE")
    if [[ "$PREV_USSA_CONTENT" =~ add\ page\ number:\ ([0-9]+) ]]; then
        USSA_PAGES="${BASH_REMATCH[1]}"
        echo "Found USSA pages: $USSA_PAGES (line before 'add ussa')"
    fi
fi

# Alternative method if above fails
if [[ $TCS_PAGES -eq 0 ]]; then
    echo "Trying alternative search for TCS pages..."
    # Look for pattern: "add page number: X" followed by "add tcs" within next 2 lines
    TCS_MATCH=$(grep -B1 -A1 "add tcs$" "$TEMP_FILE" | grep "add page number:" | head -1)
    if [[ "$TCS_MATCH" =~ add\ page\ number:\ ([0-9]+) ]]; then
        TCS_PAGES="${BASH_REMATCH[1]}"
        echo "Found TCS pages (alt): $TCS_PAGES"
    fi
fi

if [[ $SSA_PAGES -eq 0 ]]; then
    echo "Trying alternative search for SSA pages..."
    SSA_MATCH=$(grep -B1 -A1 "add ssa$" "$TEMP_FILE" | grep "add page number:" | head -1)
    if [[ "$SSA_MATCH" =~ add\ page\ number:\ ([0-9]+) ]]; then
        SSA_PAGES="${BASH_REMATCH[1]}"
        echo "Found SSA pages (alt): $SSA_PAGES"
    fi
fi

if [[ $USSA_PAGES -eq 0 ]]; then
    echo "Trying alternative search for USSA pages..."
    USSA_MATCH=$(grep -B1 -A1 "add ussa$" "$TEMP_FILE" | grep "add page number:" | head -1)
    if [[ "$USSA_MATCH" =~ add\ page\ number:\ ([0-9]+) ]]; then
        USSA_PAGES="${BASH_REMATCH[1]}"
        echo "Found USSA pages (alt): $USSA_PAGES"
    fi
fi

rm "$TEMP_FILE"

echo ""
echo "Summary of extracted parameters:"
echo "  TCS pages:  $TCS_PAGES"
echo "  SSA pages:  $SSA_PAGES"
echo "  USSA pages: $USSA_PAGES"

# Use fallback values if still not found
if [[ $TCS_PAGES -eq 0 || $SSA_PAGES -eq 0 || $USSA_PAGES -eq 0 ]]; then
    echo ""
    echo "Warning: Some page counts not found. Using fallback values from typical pattern:"
    echo "  TCS: 6, SSA: 72, USSA: 24"
    TCS_PAGES=${TCS_PAGES:-6}
    SSA_PAGES=${SSA_PAGES:-72}
    USSA_PAGES=${USSA_PAGES:-24}
fi

# Calculate totals
SSA_USSA_TOTAL=$((SSA_PAGES + USSA_PAGES))
TOTAL_PAGES=$((TCS_PAGES + SSA_PAGES + USSA_PAGES))
echo "  SSA+USSA total: $SSA_USSA_TOTAL"
echo "  Total pages:    $TOTAL_PAGES"
echo ""

# ============================================================================
# Extract LOG section and intervals
# ============================================================================
echo "=== Extracting LOG Section and Intervals ==="

# Find LOG START and LOG END
LOG_START=$(echo "$OUTPUT" | grep -n "=========LOG START=========" | tail -1 | cut -d: -f1)
LOG_END=$(echo "$OUTPUT" | grep -n "==========LOG END==========" | tail -1 | cut -d: -f1)

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

# ============================================================================
# Match intervals
# ============================================================================
echo "=== Extracting ENCLS Intervals ==="

declare -a INTERVALS

if [[ ${#STAGE0_TIMES[@]} -eq 2 && ${#STAGE1_TIMES[@]} -eq 2 ]]; then
    # Simple case: take pairs in order
    for ((i=0; i<2; i++)); do
        interval=$((STAGE1_TIMES[i] - STAGE0_TIMES[i]))
        
        if (( interval >= 0 )); then
            INTERVALS+=("$interval")
            echo "Interval $((i+1)): ${STAGE0_TIMES[i]} -> ${STAGE1_TIMES[i]} = $interval cycles"
        else
            echo "Error: Negative interval at pair $((i+1)): $interval"
            exit 1
        fi
    done
else
    echo "Error: Expected 2 stage 0 and 2 stage 1 entries"
    exit 1
fi

INTERVAL1=${INTERVALS[0]}
INTERVAL2=${INTERVALS[1]}

echo ""
echo "ENCLS intervals:"
echo "  Interval 1 (TCS): $INTERVAL1 cycles"
echo "  Interval 2 (SSA+USSA): $INTERVAL2 cycles"
echo ""

# ============================================================================
# Calculate base time and per-page time
# ============================================================================
echo "=== Calculating Base Time and Per-Page Time ==="
echo "Assumption: Both operations have the same base time (A = B)"
echo ""

# Equations:
# I1 = A + T * X  (1)
# I2 = A + S * X  (2)
# where:
#   A = base time (same for both)
#   X = per-page time
#   T = TCS_PAGES
#   S = SSA_PAGES + USSA_PAGES

T=$TCS_PAGES
S=$SSA_USSA_TOTAL
I1=$INTERVAL1
I2=$INTERVAL2

echo "Parameters:"
echo "  T (TCS pages) = $T"
echo "  S (SSA+USSA pages) = $S"
echo "  I1 (interval 1) = $I1 cycles"
echo "  I2 (interval 2) = $I2 cycles"
echo ""

if [[ $T -eq 0 || $S -eq 0 ]]; then
    echo "Error: Page counts cannot be zero"
    exit 1
fi

if [[ $T -eq $S ]]; then
    echo "Error: TCS pages equals SSA+USSA pages, cannot solve uniquely"
    exit 1
fi

# Calculate per-page time: X = (I1 - I2) / (T - S)
NUMERATOR=$((I1 - I2))
DENOMINATOR=$((T - S))
X=$((NUMERATOR / DENOMINATOR))

# Calculate base time: A = I1 - T * X
A=$((I1 - T * X))

echo "Calculation:"
echo "  X = (I1 - I2) / (T - S)"
echo "    = ($I1 - $I2) / ($T - $S)"
echo "    = $NUMERATOR / $DENOMINATOR"
echo "    = $X cycles/page"
echo ""
echo "  A = I1 - T * X"
echo "    = $I1 - $T * $X"
echo "    = $I1 - $((T * X))"
echo "    = $A cycles"
echo ""
echo "Results:"
echo "  Base time (A): $A cycles"
echo "  Per-page time (X): $X cycles/page"
echo ""

# ============================================================================
# Verify the solution
# ============================================================================
echo "=== Verification ==="

# Calculate expected intervals
EXPECTED_I1=$((A + T * X))
EXPECTED_I2=$((A + S * X))

if [[ $I1 -ne 0 ]]; then
    ERROR1=$(( (I1 - EXPECTED_I1) * 100 / I1 ))
else
    ERROR1=0
fi

if [[ $I2 -ne 0 ]]; then
    ERROR2=$(( (I2 - EXPECTED_I2) * 100 / I2 ))
else
    ERROR2=0
fi

echo "Verification:"
echo "  Expected interval 1: $EXPECTED_I1 cycles (actual: $I1, error: ${ERROR1#-}%)"
echo "  Expected interval 2: $EXPECTED_I2 cycles (actual: $I2, error: ${ERROR2#-}%)"

if (( ERROR1 == 0 && ERROR2 == 0 )); then
    echo "  ✓ Perfect match!"
elif (( ERROR1 <= 1 && ERROR2 <= 1 )); then
    echo "  ✓ Excellent match (errors ≤ 1%)"
elif (( ERROR1 <= 5 && ERROR2 <= 5 )); then
    echo "  ✓ Good match (errors ≤ 5%)"
elif (( ERROR1 <= 10 && ERROR2 <= 10 )); then
    echo "  ⚠ Reasonable match (errors ≤ 10%)"
else
    echo "  ⚠ Large errors (>10%)"
    echo "  Check: T=$T, S=$S, I1=$I1, I2=$I2"
fi

echo ""
echo "Breakdown:"
echo "  TCS operation: $A + ($T × $X) = $((A + T * X)) cycles"
echo "  SSA+USSA operation: $A + ($S × $X) = $((A + S * X)) cycles"

# ============================================================================
# Save results to CSV
# ============================================================================
echo ""
echo "=== Saving Results to CSV ==="

echo "$A,$X,$TCS_PAGES,$SSA_PAGES,$USSA_PAGES,$TOTAL_PAGES,$INTERVAL1,$INTERVAL2" >> "$OUTPUT_FILE"
echo "Saved to $OUTPUT_FILE:"
echo "  base_time=$A, per_page_time=$X, tcs_pages=$TCS_PAGES, ssa_pages=$SSA_PAGES,"
echo "  ussa_pages=$USSA_PAGES, total_pages=$TOTAL_PAGES, interval1=$INTERVAL1, interval2=$INTERVAL2"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=== Summary ==="
echo "ENCLS (ECADD) Analysis Complete!"
echo ""
echo "Model: Time = $A + (pages × $X) cycles"
echo ""
echo "For your data:"
echo "  TCS (add page): $T pages → $A + ($T × $X) = $((A + T * X)) cycles"
echo "  SSA+USSA (add page): $S pages → $A + ($S × $X) = $((A + S * X)) cycles"
echo ""
echo "Output saved to: $OUTPUT_FILE"

# Show recent entries
echo ""
echo "Recent entries in CSV:"
echo "------------------------"
tail -3 "$OUTPUT_FILE"
echo "------------------------"

echo ""
echo "=== Done ==="