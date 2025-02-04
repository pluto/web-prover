#!/bin/bash
set -ex

# A temporary script for deploying a TEE using a Dockerfile in Google Confidential Space.
# This serves as a debug tool until we refine the deployment process.

# Run `gcloud auth` to configure Google Cloud
# gcloud auth configure-docker us-central1-docker.pkg.dev

docker build -t us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest .
sleep 1
docker push us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest

instance_name="instance-$(date +%s)"

out=$(gcloud compute instances create --format=json \
  $instance_name \
  --machine-type c3-standard-4 --zone us-central1-a \
  --confidential-compute-type=TDX \
  --shielded-secure-boot \
  --maintenance-policy=TERMINATE \
  --image-family=confidential-space-debug-preview-tdx \
  --image-project=confidential-space-images \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --project tee-test-1 \
  --service-account=900397190789-compute@developer.gserviceaccount.com \
  --metadata="^~^tee-image-reference=us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest~tee-container-log-redirect=cloud_logging")

echo $out
external_ip=$(echo $out | jq -r '.[0].networkInterfaces[0].accessConfigs[0].natIP')

echo Helpful for debugging:
echo gcloud compute ssh --zone "us-central1-a" "$instance_name" --project "tee-test-1"
echo sudo ctr task exec -t --exec-id shell tee-container bash

sleep 120
curl https://$external_ip:7443/health -k
