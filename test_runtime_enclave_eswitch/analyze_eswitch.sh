#!/bin/bash

# Script: extract_eswitch.sh
# Usage: ./extract_eswitch.sh [output_file]

# Configuration
OUTPUT_FILE="${1:-eswitch.csv}"
PROGRAM="./main"

# Check if program exists
if [ ! -x "$PROGRAM" ]; then
    echo "Error: Program '$PROGRAM' not found or not executable"
    exit 1
fi

echo "=== Extract E-Switch Timings to CSV ==="
echo "Program:      $PROGRAM"
echo "Output file:  $OUTPUT_FILE"
echo "Columns:      eswitch_to_user,user_syscall1,user_syscall2,sysret"
echo "Note:         eswitch_to_user = stage1-stage0"
echo "              user_syscall1 = stage2-stage1"
echo "              user_syscall2 = stage4-stage3"
echo "              sysret = stage3-stage2"
echo ""

# Create or update CSV file with header
create_csv_with_header() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "eswitch_to_user,user_syscall1,user_syscall2,sysret" > "$file"
        echo "Created: $file with header"
    else
        # Check if file has header
        if ! head -1 "$file" | grep -q "eswitch_to_user,user_syscall1,user_syscall2,sysret"; then
            # Backup original and add header
            cp "$file" "$file.bak"
            echo "eswitch_to_user,user_syscall1,user_syscall2,sysret" > "$file"
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
# Extract eswitch timings
# ============================================================================
echo "=== Extracting ESWITCH Timings ==="

# Arrays to store timings
declare -a STAGE0_TIMES   # eswitch_tsc_addr
declare -a STAGE1_TIMES   # syscall1_tsc_addr
declare -a STAGE2_TIMES   # sysret_tsc_addr
declare -a STAGE3_TIMES   # syscall2_tsc_addr
declare -a STAGE4_TIMES   # aex_tsc_addr

ESWITCH_COUNT=0
UNMATCHED_LINES=0

echo "Looking for eswitch timing patterns..."
echo "--------------------------------------"

# Process each line of output
while IFS= read -r line; do
    # Match pattern: stage0: %lu, stage1: %lu, stage2: %lu, stage3: %lu, stage4: %lu
    if [[ "$line" =~ stage0:\ ([0-9]+),\ stage1:\ ([0-9]+),\ stage2:\ ([0-9]+),\ stage3:\ ([0-9]+),\ stage4:\ ([0-9]+) ]]; then
        stage0="${BASH_REMATCH[1]}"  # eswitch_tsc_addr
        stage1="${BASH_REMATCH[2]}"  # syscall1_tsc_addr
        stage2="${BASH_REMATCH[3]}"  # sysret_tsc_addr
        stage3="${BASH_REMATCH[4]}"  # syscall2_tsc_addr
        stage4="${BASH_REMATCH[5]}"  # aex_tsc_addr
        
        # Validate that timings are increasing (基本验证)
        if (( stage1 > stage0 && stage2 > stage1 && stage3 > stage2 && stage4 > stage3 )); then
            STAGE0_TIMES+=("$stage0")
            STAGE1_TIMES+=("$stage1")
            STAGE2_TIMES+=("$stage2")
            STAGE3_TIMES+=("$stage3")
            STAGE4_TIMES+=("$stage4")
            ESWITCH_COUNT=$((ESWITCH_COUNT + 1))
            
            echo "  Found: stage0=$stage0, stage1=$stage1, stage2=$stage2, stage3=$stage3, stage4=$stage4"
            echo "         eswitch_to_user=$((stage1 - stage0))"
            echo "         user_syscall1=$((stage2 - stage1))"
            echo "         user_syscall2=$((stage4 - stage3))"
            echo "         sysret=$((stage3 - stage2))"
        else
            echo "  Warning: Non-increasing timings - skipping line"
            echo "           stages: $stage0,$stage1,$stage2,$stage3,$stage4"
        fi
    elif [[ "$line" =~ stage[0-4]: ]] && [[ "$line" =~ [0-9]+ ]]; then
        # Found a line with stage but not the full pattern
        echo "  Note: Partial match found (not processing): $line"
        UNMATCHED_LINES=$((UNMATCHED_LINES + 1))
    fi
done <<< "$OUTPUT"

echo "--------------------------------------"
echo "Total valid eswitch entries found: $ESWITCH_COUNT"
if [[ $UNMATCHED_LINES -gt 0 ]]; then
    echo "Lines with partial matches: $UNMATCHED_LINES"
fi
echo ""

# ============================================================================
# Save to CSV
# ============================================================================
echo "=== Saving to CSV ==="

records_added=0

if [[ $ESWITCH_COUNT -eq 0 ]]; then
    echo "No valid eswitch data found. Checking for alternative formats..."
    
    # Alternative: Look for LOG section and extract stages from there
    LOG_START_LINE=$(echo "$OUTPUT" | grep -n "=========LOG START=========" | cut -d: -f1)
    LOG_END_LINE=$(echo "$OUTPUT" | grep -n "==========LOG END==========" | cut -d: -f1)
    
    if [[ -n "$LOG_START_LINE" && -n "$LOG_END_LINE" ]]; then
        echo "Found LOG section. Attempting to extract stage data from log..."
        
        # Clear arrays
        STAGE0_TIMES=()
        STAGE1_TIMES=()
        STAGE2_TIMES=()
        STAGE3_TIMES=()
        STAGE4_TIMES=()
        ESWITCH_COUNT=0
        
        # Extract LOG section
        LOG_SECTION=$(echo "$OUTPUT" | sed -n "${LOG_START_LINE},${LOG_END_LINE}p")
        
        # Arrays for each stage
        declare -a stage0_list
        declare -a stage1_list
        declare -a stage2_list
        declare -a stage3_list
        declare -a stage4_list
        
        # Extract each stage separately
        while IFS= read -r line; do
            if [[ "$line" =~ stage:\ 0,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
                TSC="${BASH_REMATCH[1]}"
                stage0_list+=("$TSC")
            elif [[ "$line" =~ stage:\ 1,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
                TSC="${BASH_REMATCH[1]}"
                stage1_list+=("$TSC")
            elif [[ "$line" =~ stage:\ 2,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
                TSC="${BASH_REMATCH[1]}"
                stage2_list+=("$TSC")
            elif [[ "$line" =~ stage:\ 3,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
                TSC="${BASH_REMATCH[1]}"
                stage3_list+=("$TSC")
            elif [[ "$line" =~ stage:\ 4,\ index:\ [0-9]+\ tsc:\ ([0-9]+) ]]; then
                TSC="${BASH_REMATCH[1]}"
                stage4_list+=("$TSC")
            fi
        done <<< "$LOG_SECTION"
        
        echo "Found stage0:${#stage0_list[@]}, stage1:${#stage1_list[@]}, stage2:${#stage2_list[@]}, stage3:${#stage3_list[@]}, stage4:${#stage4_list[@]} entries"
        
        # Try to match in quintuplets (0,1,2,3,4)
        min_length=$((${#stage0_list[@]} < ${#stage1_list[@]} ? ${#stage0_list[@]} : ${#stage1_list[@]}))
        min_length=$(($min_length < ${#stage2_list[@]} ? $min_length : ${#stage2_list[@]}))
        min_length=$(($min_length < ${#stage3_list[@]} ? $min_length : ${#stage3_list[@]}))
        min_length=$(($min_length < ${#stage4_list[@]} ? $min_length : ${#stage4_list[@]}))
        
        for ((i=0; i<min_length; i++)); do
            stage0="${stage0_list[$i]}"
            stage1="${stage1_list[$i]}"
            stage2="${stage2_list[$i]}"
            stage3="${stage3_list[$i]}"
            stage4="${stage4_list[$i]}"
            
            if (( stage1 > stage0 && stage2 > stage1 && stage3 > stage2 && stage4 > stage3 )); then
                STAGE0_TIMES+=("$stage0")
                STAGE1_TIMES+=("$stage1")
                STAGE2_TIMES+=("$stage2")
                STAGE3_TIMES+=("$stage3")
                STAGE4_TIMES+=("$stage4")
                ESWITCH_COUNT=$((ESWITCH_COUNT + 1))
                
                echo "  Matched quintuplet $i: stages $stage0,$stage1,$stage2,$stage3,$stage4"
            fi
        done
        
        echo "Matched $ESWITCH_COUNT valid quintuplets from LOG section"
    fi
fi

# Save data to CSV
if [[ $ESWITCH_COUNT -gt 0 ]]; then
    for ((i=0; i<ESWITCH_COUNT; i++)); do
        stage0="${STAGE0_TIMES[$i]}"
        stage1="${STAGE1_TIMES[$i]}"
        stage2="${STAGE2_TIMES[$i]}"
        stage3="${STAGE3_TIMES[$i]}"
        stage4="${STAGE4_TIMES[$i]}"
        
        # 根据您的需求计算：
        # 1. eswitch_to_user = stage1 - stage0
        # 2. user_syscall1 = stage2 - stage1
        # 3. user_syscall2 = stage4 - stage3
        # 4. sysret = stage3 - stage2
        eswitch_to_user=$((stage1 - stage0))
        user_syscall1=$((stage2 - stage1))
        user_syscall2=$((stage4 - stage3))
        sysret=$((stage3 - stage2))
        
        # 写入CSV，分成四列
        echo "$eswitch_to_user,$user_syscall1,$user_syscall2,$sysret" >> "$OUTPUT_FILE"
        records_added=$((records_added + 1))
    done
    
    echo ""
    echo "Added $records_added records to $OUTPUT_FILE"
    echo "Format: eswitch_to_user,user_syscall1,user_syscall2,sysret"
else
    echo "Error: No eswitch data could be extracted"
    echo "Appending N/A values as placeholder..."
    echo "N/A,N/A,N/A,N/A" >> "$OUTPUT_FILE"
    exit 1
fi

echo ""

# ============================================================================
# Show summary
# ============================================================================
echo "=== Summary ==="
echo "Total eswitch entries processed: $ESWITCH_COUNT"
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