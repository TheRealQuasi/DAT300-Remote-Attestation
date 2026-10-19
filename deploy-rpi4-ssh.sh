#!/bin/bash

RPI4=${RPI4:-rpi4-optee}
RPI4_FOLDER="${RPI4_FOLDER:-$HOME/shared/DAT300-Remote-Attestation/RPi4}"

FTPM_CA="${FTPM_CA:-$RPI4_FOLDER/CA/ra-ca-ftpm}"
TPM_CA="${TPM_CA:-$RPI4_FOLDER/CA/ra-ca-tpm}"

# FTPM
FTPM_CA_ENROLL="${CA_ENROLL:-$RPI4_FOLDER/ftpm-enroll-ssh.sh}"
FTPM_CA_BENCHMARK="${CA_BENCHMARK:-$RPI4_FOLDER/ftpm-benchmark-ssh.sh}"
FTPM_CA_DOS="${CA_DOS:-$RPI4_FOLDER/ftpm-dos-ssh.sh}"

# TPM
TPM_CA_ENROLL="${CA_ENROLL:-$RPI4_FOLDER/tpm-enroll-ssh.sh}"
TPM_CA_BENCHMARK="${CA_BENCHMARK:-$RPI4_FOLDER/tpm-benchmark-ssh.sh}"
TPM_CA_DOS="${CA_DOS:-$RPI4_FOLDER/tpm-dos-ssh.sh}"

# Build the fTPM CA
./RPi4/ftpm-build-ca.sh
./RPi4/tpm-build-ca.sh

# Copy the executable to the Raspberry Pi
scp $FTPM_CA $RPI4:~/
scp $TPM_CA $RPI4:~/

# Copy the scripts to the Raspberry Pi
scp $FTPM_CA_ENROLL $RPI4:~/
scp $FTPM_CA_BENCHMARK $RPI4:~/
scp $FTPM_CA_DOS $RPI4:~/

scp $TPM_CA_ENROLL $RPI4:~/
scp $TPM_CA_BENCHMARK $RPI4:~/
scp $TPM_CA_DOS $RPI4:~/

# Make the scripts executable on the Raspberry Pi
ssh "$RPI4" 'chmod +x ~/ftpm-enroll-ssh.sh'
ssh "$RPI4" 'chmod +x ~/ftpm-benchmark-ssh.sh'
ssh "$RPI4" 'chmod +x ~/ftpm-dos-ssh.sh'

ssh "$RPI4" 'chmod +x ~/tpm-enroll-ssh.sh'
ssh "$RPI4" 'chmod +x ~/tpm-benchmark-ssh.sh'
ssh "$RPI4" 'chmod +x ~/tpm-dos-ssh.sh'