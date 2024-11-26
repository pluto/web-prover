# TEE util

## DEBUG

```
gcloud compute instances create instance-39 \
  --machine-type c3-standard-4 --zone us-central1-a \
  --confidential-compute-type=TDX \
  --shielded-secure-boot \
  --maintenance-policy=TERMINATE \
  --image-family=confidential-space-preview-tdx \
  --image-project=confidential-space-images \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --project tee-test-1 \
  --service-account=900397190789-compute@developer.gserviceaccount.com \
  --metadata=tee-image-reference=us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest



gcloud auth configure-docker us-central1-docker.pkg.dev
docker build -t us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest .
docker push us-central1-docker.pkg.dev/tee-test-1/notary/notary:latest


curl https://$IP:7443/v1/tee/attestation -k -H "Content-type: application/json" -d '{}' -XGET

# https://docs.github.com/en/actions/use-cases-and-examples/publishing-packages/publishing-docker-images

 stat /dev/tpmrm0: no such file or directory
```