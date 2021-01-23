#!/usr/bin/env bash

aws s3 mb s3://andrewstucki-bpf-lsm
repomanage --old --keep=2 -c "$REPO" | xargs rm -f
createrepo -q ${1:+--update -c "${REPO}.cache"} --retain-old-md=3 --workers=3 --unique-md-filenames --database -d "$REPO" || die "Could not createrepo in '$REPO'"
aws s3 sync ${AWSCLI_OPTIONS[@]} "$REPO" "$REPO_URL" || die "Could not upload repo to s3"
