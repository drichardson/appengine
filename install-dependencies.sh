#!/bin/bash

set -e

# Install per https://cloud.google.com/sdk/
curl https://dl.google.com/dl/cloudsdk/channels/rapid/google-cloud-sdk.tar.gz| tar -C ~ -x -z -f -

# Answer all the gcloud installation questions so there aren't any prompts.
# Install beta components, which, at this time, contain the dev_appserver.py needed
# by google.golang.org/appengine/aetest which is used in some of the tests.
"$HOME/google-cloud-sdk/install.sh" \
    --usage-reporting true \
    --additional-components beta \
    --path-update false \
    --command-completion false
