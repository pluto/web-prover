#!/bin/bash
set -e

log() {
  echo "[INFO] $1"
}

PROJECT_NAME=$(curl -s "http://169.254.169.254/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")
GIT_HASH=$(curl -s "http://169.254.169.254/computeMetadata/v1/instance/attributes/git-hash" -H "Metadata-Flavor: Google")
ASSET_BUCKET_NAME=$(curl -s "http://169.254.169.254/computeMetadata/v1/instance/attributes/asset-bucket-name" -H "Metadata-Flavor: Google")

log "Download assets"
mkdir -p /opt/notary/assets
gcloud storage cp -r "gs://$ASSET_BUCKET_NAME/$GIT_HASH/*" /opt/notary/assets


log "Creating notary user"
if ! id -u notary &>/dev/null; then
  useradd --system --shell /usr/sbin/nologin notary
else
  log "User 'notary' already exists"
fi

log "Move assets to /opt/notary"
mkdir -p /opt/notary/{bin,etc}
mv /opt/notary/assets/notary /opt/notary/bin/notary
mv /opt/notary/assets/notary-config.toml /opt/notary/etc/
mv /opt/notary/assets/fixture /opt/notary/etc/
chmod 0755 /opt/notary/bin/notary
chown -R notary:notary /opt/notary
setcap 'cap_net_bind_service=+ep' /opt/notary/bin/notary


log "Deploying systemd service file"
mv /opt/notary/assets/notary.service /etc/systemd/system/notary.service
chown root:root /etc/systemd/system/notary.service
chmod 0644 /etc/systemd/system/notary.service


log "Delete assets"
rm -r /opt/notary/assets


log "Reloading systemd daemon"
systemctl daemon-reload


log "Starting and enabling Notary service"
systemctl enable --now notary


log "Notary deployment completed successfully"
