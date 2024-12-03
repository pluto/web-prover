#!/bin/bash
set -ex

# gcloud auth configure-docker us-central1-docker.pkg.dev
docker build -t us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest .
docker push us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest

# https://cloud.google.com/confidential-computing/confidential-space/docs/monitor-debug
# https://cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads#choose-image
# --image-family=confidential-space-debug-preview-tdx \
# --image-family=confidential-space-preview-tdx \
# https://cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads#metadata-variables

instance_name="instance-`date +%s`"

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

sleep 120

curl https://$external_ip:7443/v1/tee/attestation -k -H "Content-type: application/json" -d '{"handshake_server_aes_iv": "", "handshake_server_aes_key": "", "application_client_aes_iv": "", "application_client_aes_key": "", "application_server_aes_iv": "", "application_server_aes_key": ""}'

# gcloud compute ssh --zone "us-central1-a" "$instance_name" --project "tee-test-1"
# sudo ctr task exec -t --exec-id shell tee-container bash
