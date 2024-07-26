#!/usr/bin/env bash
# Example bin/compile script to install and configure New Relic Infrastructure Agent

# Download and extract New Relic Infrastructure Agent
echo "-----> Installing New Relic Infrastructure Agent"
wget -q -O /tmp/newrelic-infra.tar.gz https://download.newrelic.com/infrastructure_agent/linux/apt/pool/main/n/newrelic-infra/newrelic-infra_1.53.0_amd64.deb
tar -xzvf /tmp/newrelic-infra.tar.gz -C /app
rm /tmp/newrelic-infra.tar.gz

# Retrieve New Relic License Key from Cloud Foundry environment
NEW_RELIC_LICENSE_KEY=${NEW_RELIC_LICENSE_KEY:-}
if [ -z "${NEW_RELIC_LICENSE_KEY}" ]; then
    echo "ERROR: NEW_RELIC_LICENSE_KEY environment variable not set."
    exit 1
fi

# Configure New Relic Infrastructure Agent
echo "-----> Configuring New Relic Infrastructure Agent"
cat << EOF > /app/newrelic-infra/newrelic-infra.yml
license_key: ${NEW_RELIC_LICENSE_KEY}
EOF

# Start New Relic Infrastructure Agent
echo "-----> Starting New Relic Infrastructure Agent"
/app/newrelic-infra/newrelic-infra start

echo "-----> Buildpack compilation finished successfully"

