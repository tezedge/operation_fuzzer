#!/bin/sh

mkdir log/
docker run --cap-add=SYS_PTRACE --net host -v $(pwd)/log:/log -v /var/lib/fuzzing-data/reports/:/coverage -ti fuzz_op
