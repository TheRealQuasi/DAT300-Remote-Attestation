#!/bin/bash

RPI4=${RPI4:-rpi4-optee}
RPI4_FOLDER="${RPI4_FOLDER:-$HOME/shared/DAT300-Remote-Attestation/RPi4}"

CA="${CA:-$RPI4_FOLDER/CA/ra-ca-ftpm}"
CA_ENROLL="${CA_ENROLL:-$RPI4_FOLDER/ftpm-enroll-ssh.sh}"
CA_BENCHMARK="${CA_BENCHMARK:-$RPI4_FOLDER/ftpm-benchmark-ssh.sh}"

# Build the fTPM CA
./RPi4/ftpm-build-ca.sh

# Copy the executable to the Raspberry Pi
scp $CA $RPI4:~/

# Copy the scripts to the Raspberry Pi
scp $CA_ENROLL $RPI4:~/
scp $CA_BENCHMARK $RPI4:~/
ssh "$RPI4" 'chmod +x ~/ftpm-enroll-ssh.sh'
ssh "$RPI4" 'chmod +x ~/ftpm-benchmark-ssh.sh'