#!/bin/bash

# Script: parse_log_v2_split.sh
# Usage: ./parse_log_v2_split.sh [output_prefix]

# Configuration
OUTPUT_PREFIX="${1:-analysis}"
PROGRAM="./main"

# Output files
ENCLU_FIRST_CSV="${OUTPUT_PREFIX}_enclu_first.csv"
ENCLU_AFTER_CSV="${OUTPUT_PREFIX}_enclu_after.csv"
AEX_CSV="${OUTPUT_PREFIX}_aex.csv"
EEXIT_CSV="${OUTPUT_PREFIX}_eexit.csv"

# Check if program exists
if [ ! -x "$PROGRAM" ]; then
    echo "Error: Program '$PROGRAM' not found or not executable"
    exit 1
fi

echo "=== TEEVisor Log Parser v2.2 (Split ENCLU output) ==="
echo "Program:     $PROGRAM"
echo "Output prefix: $OUTPUT_PREFIX"
echo "ENCLU First:  $ENCLU_FIRST_CSV"
echo "ENCLU After:  $ENCLU_AFTER_CSV"
echo "AEX output:   $AEX_CSV"
echo "EExit output: $EEXIT_CSV"
echo "CPU core:    0 (using taskset)"
echo ""

# Create CSV files with headers if they don't exist
create_csv_with_header() {
    local file="$1"
    local header="$2"
    
    if [ ! -f "$file" ]; then
        echo "$header" > "$file"
        echo "Created: $file"
    else
        echo "Appending to: $file"
    fi
}

create_csv_with_header "$ENCLU_FIRST_CSV" "stage_m1_tsc,stage0_tsc,stage2_tsc,stage4_tsc,driver_interval_tsc,context_switch_tsc,svsm_tsc,total_time"
create_csv_with_header "$ENCLU_AFTER_CSV" "stage_m1_tsc,stage0_tsc,stage2_tsc,stage4_tsc,driver_interval_tsc,context_switch_tsc,svsm_tsc,total_time"
create_csv_with_header "$AEX_CSV" "aex_tsc,stage3_tsc,stage1_tsc,aex_to_svsm_end_tsc,context_switch_tsc,total_aex_phase"
create_csv_with_header "$EEXIT_CSV" "eexit_tsc,stage3_tsc,stage1_tsc,current_tsc,eexit_to_stage3,stage3_to_stage1,stage1_to_current,total_eexit_phase"

echo ""

# Run program with taskset and capture output
echo "Running: taskset -c 0 $PROGRAM"
echo "------------------------------------------------------------"

# Run the program and capture output
OUTPUT=$(taskset -c 0 "$PROGRAM" 2>&1)
echo "$OUTPUT"
echo "------------------------------------------------------------"
echo ""

# Check if we got any output
if [ -z "$OUTPUT" ]; then
    echo "Warning: Program produced no output"
    echo "Appending N/A values to CSV files..."
    echo "N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$ENCLU_FIRST_CSV"
    echo "N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$ENCLU_AFTER_CSV"
    echo "N/A,N/A,N/A,N/A,N/A,N/A" >> "$AEX_CSV"
    echo "N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$EEXIT_CSV"
    exit 0
fi

# ============================================================================
# Extract all data from output
# ============================================================================
echo "=== Extracting Data ==="

# Extract all stage data and sort them by timestamp
declare -a STAGE_TIMES STAGE_NUMS STAGE_INDICES
STAGE_COUNT=0

while IFS= read -r line; do
    if [[ "$line" =~ stage:\ (-?[0-9]+),\ index:\ ([0-9]+)\ tsc:\ ([0-9]+) ]]; then
        STAGE="${BASH_REMATCH[1]}"
        INDEX="${BASH_REMATCH[2]}"
        TSC="${BASH_REMATCH[3]}"
        STAGE_TIMES+=("$TSC")
        STAGE_NUMS+=("$STAGE")
        STAGE_INDICES+=("$INDEX")
        STAGE_COUNT=$((STAGE_COUNT + 1))
    fi
done <<< "$OUTPUT"

echo "Found $STAGE_COUNT stage entries"

# Sort stages by timestamp (using bubble sort for simplicity)
for ((i=0; i<STAGE_COUNT-1; i++)); do
    for ((j=0; j<STAGE_COUNT-i-1; j++)); do
        if [[ ${STAGE_TIMES[j]} -gt ${STAGE_TIMES[j+1]} ]]; then
            # Swap times
            temp_tsc=${STAGE_TIMES[j]}
            STAGE_TIMES[j]=${STAGE_TIMES[j+1]}
            STAGE_TIMES[j+1]=$temp_tsc
            
            # Swap stage numbers
            temp_stage=${STAGE_NUMS[j]}
            STAGE_NUMS[j]=${STAGE_NUMS[j+1]}
            STAGE_NUMS[j+1]=$temp_stage
            
            # Swap indices
            temp_idx=${STAGE_INDICES[j]}
            STAGE_INDICES[j]=${STAGE_INDICES[j+1]}
            STAGE_INDICES[j+1]=$temp_idx
        fi
    done
done

echo ""
echo "Sorted stage entries (first 20):"
for i in {0..19}; do
    if [ -n "${STAGE_TIMES[$i]:-}" ]; then
        printf "  %3d: %20d | Stage %2s (idx %s)\n" "$i" "${STAGE_TIMES[$i]}" "${STAGE_NUMS[$i]}" "${STAGE_INDICES[$i]}"
    fi
done
echo ""

# Extract AEX/EExit/current triplets
AEX_EEXIT_CURRENT_TRIPLETS=()
while IFS= read -r line; do
    if [[ "$line" =~ aex_tsc:\ ([0-9]+),\ eexit_tsc:\ ([0-9]+),\ current_tsc:\ ([0-9]+) ]]; then
        AEX_TSCO="${BASH_REMATCH[1]}"
        EEXIT_TSCO="${BASH_REMATCH[2]}"
        CURRENT_TSCO="${BASH_REMATCH[3]}"
        AEX_EEXIT_CURRENT_TRIPLETS+=("$AEX_TSCO:$EEXIT_TSCO:$CURRENT_TSCO")
    fi
done <<< "$OUTPUT"

echo "Found ${#AEX_EEXIT_CURRENT_TRIPLETS[@]} AEX/EExit/current triplets"
for i in "${!AEX_EEXIT_CURRENT_TRIPLETS[@]}"; do
    IFS=':' read -r aex eexit current <<< "${AEX_EEXIT_CURRENT_TRIPLETS[$i]}"
    echo "  Triplet $((i+1)): AEX=$aex, EExit=$eexit, Current=$current"
done
echo ""

# ============================================================================
# Functions
# ============================================================================

# Function to find complete sequences: stage -1 -> stage 0 -> stage 2 -> stage 4
find_complete_sequences_split() {
    local sequence_counter=0
    local first_sequence_found=0
    local -a used_indices
    
    echo "Searching for complete sequences (-1 -> 0 -> 2 -> 4)..."
    
    # We'll go through all stage -1 entries
    for ((i=0; i<STAGE_COUNT; i++)); do
        if [[ "${STAGE_NUMS[$i]}" == "-1" ]]; then
            local stage_m1="${STAGE_TIMES[$i]}"
            local stage_m1_idx="$i"
            
            # Skip if already used
            if [[ " ${used_indices[@]} " =~ " $i " ]]; then
                continue
            fi
            
            # Look for the next stage 0 after this stage -1
            local stage0=""
            local stage0_idx=""
            for ((j=i+1; j<STAGE_COUNT; j++)); do
                if [[ "${STAGE_NUMS[$j]}" == "0" && ! " ${used_indices[@]} " =~ " $j " ]]; then
                    stage0="${STAGE_TIMES[$j]}"
                    stage0_idx="$j"
                    break
                fi
            done
            
            if [[ -z "$stage0" ]]; then
                continue
            fi
            
            # Look for the next stage 2 after this stage 0
            local stage2=""
            local stage2_idx=""
            for ((j=stage0_idx+1; j<STAGE_COUNT; j++)); do
                if [[ "${STAGE_NUMS[$j]}" == "2" && ! " ${used_indices[@]} " =~ " $j " ]]; then
                    stage2="${STAGE_TIMES[$j]}"
                    stage2_idx="$j"
                    break
                fi
            done
            
            if [[ -z "$stage2" ]]; then
                continue
            fi
            
            # Look for the next stage 4 after this stage 2
            local stage4=""
            local stage4_idx=""
            for ((j=stage2_idx+1; j<STAGE_COUNT; j++)); do
                if [[ "${STAGE_NUMS[$j]}" == "4" && ! " ${used_indices[@]} " =~ " $j " ]]; then
                    stage4="${STAGE_TIMES[$j]}"
                    stage4_idx="$j"
                    break
                fi
            done
            
            if [[ -z "$stage4" ]]; then
                continue
            fi
            
            # We found a complete sequence!
            sequence_counter=$((sequence_counter + 1))
            
            # Calculate intervals
            time1=$((stage0 - stage_m1))
            time2=$((stage2 - stage0))
            time3=$((stage4 - stage2))
            total_time=$((stage4 - stage_m1))
            
            # Check for negative intervals
            if (( time1 < 0 || time2 < 0 || time3 < 0 )); then
                echo "  ⚠ Warning: Negative interval detected in sequence #$sequence_counter, skipping..."
                continue
            fi
            
            # Determine if this is the first complete sequence
            if [[ $first_sequence_found -eq 0 ]]; then
                echo "  ✓ Found FIRST complete sequence #$sequence_counter!"
                first_sequence_found=1
                echo "    Stage -1: $stage_m1 (idx $stage_m1_idx)"
                echo "    Stage 0:  $stage0 (idx $stage0_idx)"
                echo "    Stage 2:  $stage2 (idx $stage2_idx)"
                echo "    Stage 4:  $stage4 (idx $stage4_idx)"
                echo "    Intervals: time1=$time1, time2=$time2, time3=$time3, total=$total_time cycles"
                
                # Write to ENCLU_FIRST_CSV
                echo "$stage_m1,$stage0,$stage2,$stage4,$time1,$time2,$time3,$total_time" >> "$ENCLU_FIRST_CSV"
            else
                echo "  ✓ Found AFTER sequence #$sequence_counter"
                echo "    Stage -1: $stage_m1 (idx $stage_m1_idx)"
                echo "    Stage 0:  $stage0 (idx $stage0_idx)"
                echo "    Stage 2:  $stage2 (idx $stage2_idx)"
                echo "    Stage 4:  $stage4 (idx $stage4_idx)"
                echo "    Intervals: time1=$time1, time2=$time2, time3=$time3, total=$total_time cycles"
                
                # Write to ENCLU_AFTER_CSV
                echo "$stage_m1,$stage0,$stage2,$stage4,$time1,$time2,$time3,$total_time" >> "$ENCLU_AFTER_CSV"
            fi
            
            # Mark all stages in this sequence as used
            used_indices+=("$stage_m1_idx" "$stage0_idx" "$stage2_idx" "$stage4_idx")
        fi
    done
    
    echo ""
    echo "Total complete sequences found: $sequence_counter"
    if [[ $first_sequence_found -eq 0 ]]; then
        echo "Warning: No complete sequences found!"
    fi
    echo "Used stage indices: ${used_indices[@]}"
    
    # Return used indices array
    eval "$1='${used_indices[@]}'"
}

# Function to find stage3->stage1 sequence after a timestamp (excluding used stages)
find_stage3_stage1_after() {
    local start_tsc="$1"
    local used_indices="$2"
    local stage3_ref=""
    local stage1_ref=""
    local stage3_idx=""
    local stage1_idx=""
    
    for ((i=0; i<STAGE_COUNT; i++)); do
        # Skip used stages
        if [[ " $used_indices " =~ " $i " ]]; then
            continue
        fi
        
        local tsc="${STAGE_TIMES[$i]}"
        local stage="${STAGE_NUMS[$i]}"
        
        # We need to find stage3 first, then stage1
        if (( tsc > start_tsc )) && [[ "$stage" == "3" && -z "$stage3_ref" ]]; then
            stage3_ref="$tsc"
            stage3_idx="$i"
            
            # Now look for stage1 after this stage3
            for ((j=i+1; j<STAGE_COUNT; j++)); do
                if [[ " $used_indices " =~ " $j " ]]; then
                    continue
                fi
                
                local tsc_j="${STAGE_TIMES[$j]}"
                local stage_j="${STAGE_NUMS[$j]}"
                
                if [[ "$stage_j" == "1" && -z "$stage1_ref" ]]; then
                    stage1_ref="$tsc_j"
                    stage1_idx="$j"
                    break
                fi
            done
            
            break
        fi
    done
    
    # Return values and indices
    eval "$3='$stage3_ref'"
    eval "$4='$stage1_ref'"
    eval "$5='$stage3_idx'"
    eval "$6='$stage1_idx'"
}

# ============================================================================
# 1. ENCLU Analysis: Find complete sequences stage -1 -> stage 0 -> stage 2 -> stage 4
# ============================================================================
echo "=== ENCLU Analysis (Stage -1 -> Stage 0 -> Stage 2 -> Stage 4) ==="

used_enclu_indices=""
find_complete_sequences_split used_enclu_indices

# ============================================================================
# 2. AEX and EExit Analysis
# ============================================================================
echo ""
echo "=== AEX and EExit Analysis ==="

# Process each AEX/EExit/current triplet
if [ ${#AEX_EEXIT_CURRENT_TRIPLETS[@]} -gt 0 ]; then
    triplet_counter=0
    
    for triplet in "${AEX_EEXIT_CURRENT_TRIPLETS[@]}"; do
        IFS=':' read -r aex_tsc eexit_tsc current_tsc <<< "$triplet"
        triplet_counter=$((triplet_counter + 1))
        
        echo ""
        echo "=== Processing Triplet $triplet_counter ==="
        echo "AEX:      $aex_tsc"
        echo "EExit:    $eexit_tsc"
        echo "Current:  $current_tsc"
        echo ""
        
        # --------------------------------------------------------------------
        # AEX Analysis
        # --------------------------------------------------------------------
        echo "AEX Analysis: Looking for stage3->stage1 after AEX..."
        
        aex_stage3=""
        aex_stage1=""
        aex_stage3_idx=""
        aex_stage1_idx=""
        find_stage3_stage1_after "$aex_tsc" "$used_enclu_indices" aex_stage3 aex_stage1 aex_stage3_idx aex_stage1_idx
        
        if [[ -n "$aex_stage3" && -n "$aex_stage1" ]]; then
            # Calculate intervals (去掉stage1到current的计算)
            aex_to_stage3=$((aex_stage3 - aex_tsc))
            stage3_to_stage1=$((aex_stage1 - aex_stage3))
            # AEX总时间: AEX -> Stage1
            total_aex=$((aex_stage1 - aex_tsc))
            
            echo "  ✓ Found stage 3 -> stage 1 sequence"
            echo "    Stage 3 at $aex_stage3 (idx $aex_stage3_idx)"
            echo "    Stage 1 at $aex_stage1 (idx $aex_stage1_idx)"
            echo ""
            echo "    Intervals:"
            echo "    - AEX -> Stage 3:   $aex_to_stage3 cycles"
            echo "    - Stage 3 -> Stage 1: $stage3_to_stage1 cycles"
            echo "    - Total (AEX->Stage1): $total_aex cycles"
            
            # Check for negative intervals
            if (( aex_to_stage3 < 0 || stage3_to_stage1 < 0 )); then
                echo "  ⚠ Warning: Negative interval detected in AEX analysis!"
            fi
            
            # Write to AEX CSV (6列，符合新的header)
            echo "$aex_tsc,$aex_stage3,$aex_stage1,$aex_to_stage3,$stage3_to_stage1,$total_aex" >> "$AEX_CSV"
            
            # Add to used indices
            used_enclu_indices="$used_enclu_indices $aex_stage3_idx $aex_stage1_idx"
        else
            echo "  ✗ Could not find Stage 3 -> Stage 1 sequence after AEX"
            # Still write with available data (6列N/A)
            aex_to_stage3="N/A"
            stage3_to_stage1="N/A"
            total_aex="N/A"
            echo "$aex_tsc,$aex_stage3,$aex_stage1,$aex_to_stage3,$stage3_to_stage1,$total_aex" >> "$AEX_CSV"
        fi
        
        echo ""
        
        # --------------------------------------------------------------------
        # EExit Analysis
        # --------------------------------------------------------------------
        echo "EExit Analysis: Looking for stage3->stage1 after EExit..."
        
        eexit_stage3=""
        eexit_stage1=""
        eexit_stage3_idx=""
        eexit_stage1_idx=""
        find_stage3_stage1_after "$eexit_tsc" "$used_enclu_indices" eexit_stage3 eexit_stage1 eexit_stage3_idx eexit_stage1_idx
        
        if [[ -n "$eexit_stage3" && -n "$eexit_stage1" ]]; then
            # Calculate all intervals (保留stage1到current的计算)
            eexit_to_stage3=$((eexit_stage3 - eexit_tsc))
            stage3_to_stage1=$((eexit_stage1 - eexit_stage3))
            stage1_to_current=$((current_tsc - eexit_stage1))
            total_eexit=$((eexit_to_stage3 + stage3_to_stage1 + stage1_to_current))
            
            echo "  ✓ Found stage 3 -> stage 1 sequence"
            echo "    Stage 3 at $eexit_stage3 (idx $eexit_stage3_idx)"
            echo "    Stage 1 at $eexit_stage1 (idx $eexit_stage1_idx)"
            echo "    Current at $current_tsc"
            echo ""
            echo "    Intervals:"
            echo "    - EExit -> Stage 3:  $eexit_to_stage3 cycles"
            echo "    - Stage 3 -> Stage 1: $stage3_to_stage1 cycles"
            echo "    - Stage 1 -> Current: $stage1_to_current cycles"
            echo "    - Total (EExit->Current): $total_eexit cycles"
            
            # Check for negative intervals
            if (( eexit_to_stage3 < 0 || stage3_to_stage1 < 0 )); then
                echo "  ⚠ Warning: Negative interval detected in EExit analysis!"
            fi
            
            if (( stage1_to_current < 0 )); then
                echo "  ⚠ Warning: Stage 1 ($eexit_stage1) is AFTER Current ($current_tsc)!"
            fi
            
            # Write to EExit CSV (8列，符合新的header)
            echo "$eexit_tsc,$eexit_stage3,$eexit_stage1,$current_tsc,$eexit_to_stage3,$stage3_to_stage1,$stage1_to_current,$total_eexit" >> "$EEXIT_CSV"
            
            # Add to used indices
            used_enclu_indices="$used_enclu_indices $eexit_stage3_idx $eexit_stage1_idx"
        else
            echo "  ✗ Could not find Stage 3 -> Stage 1 sequence after EExit"
            # Still write with available data (8列N/A)
            stage1_to_current="N/A"
            total_eexit="N/A"
            eexit_to_stage3=$([ -n "$eexit_stage3" ] && echo $((eexit_stage3 - eexit_tsc)) || echo "N/A")
            stage3_to_stage1="N/A"
            echo "$eexit_tsc,$eexit_stage3,$eexit_stage1,$current_tsc,$eexit_to_stage3,$stage3_to_stage1,$stage1_to_current,$total_eexit" >> "$EEXIT_CSV"
        fi
        
        echo "====================================="
    done
    
    echo ""
    echo "Processed $triplet_counter AEX/EExit/current triplets"
else
    echo "No AEX/EExit/current triplets found"
    echo "N/A,N/A,N/A,N/A,N/A,N/A" >> "$AEX_CSV"
    echo "N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$EEXIT_CSV"
fi

echo ""

# ============================================================================
# Debug: Show remaining unused stages
# ============================================================================
echo "=== Debug: Remaining Unused Stages ==="
unused_count=0
echo "Used indices: $used_enclu_indices"
echo ""

for ((i=0; i<STAGE_COUNT; i++)); do
    if [[ ! " $used_enclu_indices " =~ " $i " ]]; then
        unused_count=$((unused_count + 1))
        if (( unused_count <= 20 )); then
            printf "  %3d: %20d | Stage %2s (idx %s)\n" "$i" "${STAGE_TIMES[$i]}" "${STAGE_NUMS[$i]}" "${STAGE_INDICES[$i]}"
        fi
    fi
done

if (( unused_count > 20 )); then
    echo "  ... and $((unused_count - 20)) more"
fi
echo "Total unused stages: $unused_count"

# ============================================================================
# Final Summary
# ============================================================================
echo ""
echo "=== Analysis Complete ==="
echo ""
echo "Summary of generated files:"

CSV_FILES=("$ENCLU_FIRST_CSV" "$ENCLU_AFTER_CSV" "$AEX_CSV" "$EEXIT_CSV")
CSV_NAMES=("ENCLU First" "ENCLU After" "AEX" "EExit")

for i in "${!CSV_FILES[@]}"; do
    CSV_FILE="${CSV_FILES[$i]}"
    CSV_NAME="${CSV_NAMES[$i]}"
    
    if [ -f "$CSV_FILE" ]; then
        TOTAL_LINES=$(wc -l < "$CSV_FILE")
        DATA_ROWS=$((TOTAL_LINES - 1))
        echo ""
        echo "$CSV_NAME ($(basename "$CSV_FILE")):"
        echo "  Total entries: $DATA_ROWS"
        
        if [ "$DATA_ROWS" -gt 0 ]; then
            echo "  First entry: $(sed -n '2p' "$CSV_FILE")"
            if [ "$DATA_ROWS" -gt 1 ]; then
                echo "  Last entry:  $(tail -1 "$CSV_FILE")"
            fi
        fi
    fi
done

echo ""
echo "=== Important Note ==="
echo "First complete ENCLU sequence saved to: $ENCLU_FIRST_CSV"
echo "All subsequent ENCLU sequences saved to: $ENCLU_AFTER_CSV"