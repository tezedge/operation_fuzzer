#!/bin/sh

mkdir -p log/
docker run -d --cap-add=SYS_PTRACE --net host -v $(pwd)/log:/log -v /var/lib/fuzzing-data/reports/:/coverage -ti fuzz_op
