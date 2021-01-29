#!/usr/bin/env bash

aws s3 mb s3://andrewstucki-bpf-lsm
createrepo -q --retain-old-md=3 --workers=3 --unique-md-filenames --database -d rpms
aws s3 sync rpms s3://andrewstucki-bpf-lsm --acl public-read
