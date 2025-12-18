#!/bin/bash

# Script: run_all_measurements.sh
# Usage: ./run_all_measurements.sh [test_rounds]

# Get TEST_ROUND from environment variable or command line argument
if [[ -n "$TEST_ROUND" ]]; then
    TEST_ROUNDS="$TEST_ROUND"
    echo "Using TEST_ROUND from environment: $TEST_ROUNDS"
elif [[ -n "$1" && "$1" =~ ^[0-9]+$ ]]; then
    TEST_ROUNDS="$1"
    echo "Using TEST_ROUND from command line: $TEST_ROUNDS"
else
    TEST_ROUNDS=1
    echo "Using default TEST_ROUND: $TEST_ROUNDS"
fi

# Create logs directory if it doesn't exist
LOGS_DIR="/logs"
mkdir -p "$LOGS_DIR"
echo "All CSV files will be saved to: $LOGS_DIR"
echo ""

echo "=== Starting All Measurements ==="
echo "Total test rounds: $TEST_ROUNDS"
echo "================================="
echo ""

# Function to move all CSV files from a directory to logs directory
move_all_csv_to_logs() {
    local source_dir="$1"
    
    if [[ -n "$source_dir" && -d "$source_dir" ]]; then
        # Move all CSV files
        for csv_file in "$source_dir"/*.csv; do
            if [[ -f "$csv_file" ]]; then
                local base_name=$(basename "$csv_file")
                mv "$csv_file" "$LOGS_DIR/"
                echo "  Moved $base_name to $LOGS_DIR/"
            fi
        done
    fi
}

# Function to run measurement for multiple rounds
run_measurement_rounds() {
    local measurement_name="$1"
    local test_dir="$2"
    local command_script="$3"
    local command_args="$4"
    local rounds="$5"
    
    echo "=== $measurement_name (Total rounds: $rounds) ==="
    
    for ((round=1; round<=rounds; round++)); do
        echo "Round $round/$rounds..."
        
        # Change to test directory, run command, then return
        if [[ -d "$test_dir" ]]; then
            cd "$test_dir"
            if [[ -n "$command_args" ]]; then
                ./"$command_script" "$command_args" > /dev/null
            else
                ./"$command_script" > /dev/null
            fi
            cd ..
        else
            echo "  Error: Directory $test_dir not found"
        fi
        
        # Wait a bit between rounds to ensure clean state
        sleep 0.1
    done

    # Move all CSV files to logs directory
    move_all_csv_to_logs "$test_dir"
    
    echo "Completed $measurement_name ($rounds rounds)"
    echo ""
}

# Special function for ECADD measurement
run_ecadd_measurement_rounds() {
    local measurement_name="$1"
    local rounds="$2"
    
    echo "=== $measurement_name (Total rounds: $rounds) ==="
    
    for ((round=1; round<=rounds; round++)); do
        echo "Round $round/$rounds..."
        
        # ECADD runs for TCS 1-5 in sequence
        if [[ -d "./test_runtime_enclave_clone_ecadd" ]]; then
            cd ./test_runtime_enclave_clone_ecadd
            for tcs in 1 2 3 4 5; do
                echo "  Running TCS $tcs..."
                ./analyze_ecadd.sh $tcs > /dev/null
            done
            cd ..
        else
            echo "  Error: Directory ./test_runtime_enclave_clone_ecadd not found"
        fi
        
        # Wait a bit between rounds
        sleep 0.1
    done

    # Move all CSV files to logs directory
    move_all_csv_to_logs "./test_runtime_enclave_clone_ecadd"
    
    echo "Completed $measurement_name ($rounds rounds)"
    echo ""
}

# Special function for ECLONE measurement
run_eclone_measurement_rounds() {
    local measurement_name="$1"
    local rounds="$2"
    
    echo "=== $measurement_name (Total rounds: $rounds) ==="
    
    for ((round=1; round<=rounds; round++)); do
        echo "Round $round/$rounds..."
        
        # ECLONE runs for TCS 1-5 in sequence
        if [[ -d "./test_runtime_enclave_clone_eclone" ]]; then
            cd ./test_runtime_enclave_clone_eclone
            for tcs in 1 2 3 4 5; do
                echo "  Running TCS $tcs..."
                ./analyze_eclone.sh $tcs > /dev/null
            done
            cd ..
        else
            echo "  Error: Directory ./test_runtime_clone_eclone not found"
        fi
        
        # Wait a bit between rounds
        sleep 0.1
    done

    # Move all CSV files to logs directory
    move_all_csv_to_logs "./test_runtime_enclave_clone_eclone"
    
    echo "Completed $measurement_name ($rounds rounds)"
    echo ""
}

# ============================================================================
# Main measurement execution
# ============================================================================

echo "Start Measuring ENCLU(EENTER, ERESUME, AEX, EEXIT)"

echo 0 > /sys/module/teevisor/parameters/measure_index
echo 1 > /sys/module/teevisor/parameters/enclu_detail

# Build with LOG=2 for first set of measurements
make clean > /dev/null && make LOG=2 > /dev/null 2>&1

# Run ENCLU measurements
run_measurement_rounds "ENCLU" \
    "test_normal_enclave_enclu" \
    "analyze_enclu.sh" \
    "" \
    "$TEST_ROUNDS"

make clean > /dev/null && make LOG=1 > /dev/null 2>&1
echo 0 > /sys/module/teevisor/parameters/enclu_detail

# ============================================================================
# Single-instruction measurements (each runs TEST_ROUNDS times)
# ============================================================================

echo "Start Measuring EAUG"
echo 5 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EAUG" \
    "test_normal_enclave_eaug" \
    "analyze_eaug.sh" \
    "" \
    "$TEST_ROUNDS"

echo "Start Measuring EADDB"
echo 14 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EADDB" \
    "test_normal_enclave_encls" \
    "analyze_eaddb.sh" \
    "" \
    "$TEST_ROUNDS"

echo "Start Measuring ECREATE"
echo 1 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECREATE" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "ecreate.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EDBGRD"
echo 12 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EDBGRD" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "edbgrd.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EDBGWR"
echo 13 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EDBGWR" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "edbgwr.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EMODPR"
echo 10 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EMODPR" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "emodpr.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EMODT"
echo 11 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EMODT" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "emodt.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EINIT"
echo 4 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EINIT" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "einit.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EREMOVE"
echo 8 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "EREMOVE" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "eremove.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ESYNC"
echo 9 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ESYNC" \
    "test_normal_enclave_encls" \
    "analyze_encls.sh" \
    "esync.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECABORT"
echo 17 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECABORT" \
    "test_runtime_enclave_clone_ecabort" \
    "analyze_encls.sh" \
    "ecabort.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECADD"
echo 15 > /sys/module/teevisor/parameters/measure_index
run_ecadd_measurement_rounds "ECADD" "$TEST_ROUNDS"

echo "Start Measuring ECCREATE"
echo 6 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECCREATE" \
    "test_runtime_enclave_clone_normal" \
    "analyze_encls.sh" \
    "eccreate.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECLONEINFO"
echo 7 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECLONEINFO" \
    "test_runtime_enclave_clone_normal" \
    "analyze_encls.sh" \
    "ecloneinfo.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECINIT"
echo 16 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECINIT" \
    "test_runtime_enclave_clone_normal" \
    "analyze_encls.sh" \
    "ecinit.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECADDCACHE"
echo 18 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECADDCACHE" \
    "test_runtime_enclave_clone_cache" \
    "analyze_encls.sh" \
    "ecaddcache.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECCLEARCACHE"
echo 19 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECCleARCACHE" \
    "test_runtime_enclave_clone_cache" \
    "analyze_encls.sh" \
    "ecclearcache.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ECSYNC"
echo 20 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "ECSYNC" \
    "test_runtime_enclave_clone_normal" \
    "analyze_encls.sh" \
    "ecsync.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring CLONE TOTAL time"
echo 100 > /sys/module/teevisor/parameters/measure_index
run_measurement_rounds "CLONE_TOTAL" \
    "test_runtime_enclave_clone_normal" \
    "analyze_encls.sh" \
    "clone_total.csv" \
    "$TEST_ROUNDS"

# ============================================================================
# ENCLU within ENCLAVE measurements
# ============================================================================

# Set a non-existing index
echo 50 > /sys/module/teevisor/parameters/measure_index
echo "Start Measuring ENCLU within ENCLAVE"
echo "Start Measuring EACCEPT"
run_measurement_rounds "EACCEPT" \
    "test_normal_enclave_eaccept" \
    "analyze_enclu.sh" \
    "eaccept.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EGETKEY"
run_measurement_rounds "EGETKEY" \
    "test_normal_enclave_egetkey" \
    "analyze_enclu.sh" \
    "egetkey.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EMODPE"
run_measurement_rounds "EMODPE" \
    "test_normal_enclave_emodpe" \
    "analyze_enclu.sh" \
    "emodpe.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EREPORT"
run_measurement_rounds "EREPORT" \
    "test_normal_enclave_ereport" \
    "analyze_enclu.sh" \
    "ereport.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring EMODP"
run_measurement_rounds "EMODP" \
    "test_runtime_enclave_emodp" \
    "analyze_enclu.sh" \
    "emodp.csv" \
    "$TEST_ROUNDS"

echo "Start Measuring ESETUSSA"
run_measurement_rounds "ESETUSSA" \
    "test_runtime_enclave_esetussa" \
    "analyze_enclu.sh" \
    "esetussa.csv" \
    "$TEST_ROUNDS"

# ============================================================================
# Special measurements with different LOG levels
# ============================================================================

make clean > /dev/null && make LOG=3 > /dev/null 2>&1

echo "Start Measuring ESWITCH and syscall"
run_measurement_rounds "ESWITCH" \
    "test_runtime_enclave_eswitch" \
    "analyze_eswitch.sh" \
    "" \
    "$TEST_ROUNDS"

echo 0 > /sys/module/teevisor/parameters/measure_index

echo "Start Measuring exception delay and ERAISE"
run_measurement_rounds "ERAISE" \
    "test_runtime_enclave_eraise" \
    "analyze_eraise.sh" \
    "" \
    "$TEST_ROUNDS"

echo "Start Measuring ECLONE delay"
run_eclone_measurement_rounds "ECLONE" "$TEST_ROUNDS"

# ============================================================================
# Final cleanup and summary
# ============================================================================

echo 0 > /sys/module/teevisor/parameters/measure_index

# List all CSV files in logs directory
echo ""
echo "========================================="
echo "All measurements completed successfully!"
echo "Total rounds executed: $TEST_ROUNDS"
echo ""
echo "CSV files saved to: $LOGS_DIR"
echo "-----------------------------------------"
ls -la "$LOGS_DIR"/*.csv 2>/dev/null | head -30
echo "-----------------------------------------"
TOTAL_FILES=$(ls "$LOGS_DIR"/*.csv 2>/dev/null | wc -l)
echo "Total CSV files: $TOTAL_FILES"