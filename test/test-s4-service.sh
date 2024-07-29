#!/bin/bash

VERSION="1.0.1"

cf create-org nr-org
cf target -o "nr-org"
cf create-space nr-space01
cf target -o "nr-org" -s "nr-space01"
cf buildpacks
unzip newrelic-pcf-nginx-buildpack-${VERSION}.pivotal -d buildpack_tile
cd buildpack_tile
cd releases
mkdir tmp
tar xvf newrelic-pcf-nginx-buildpack-${VERSION}.tgz -C tmp
cd tmp/packages
tar xvf newrelic_nginx_buildpack_cflinuxfs4.tgz
cf create-buildpack newrelic_nginx_buildpack-local newrelic_nginx_buildpack_cflinuxfs4/newrelic_nginx_buildpack-cached-cflinuxfs4-v${VERSION}.zip 98
cd ../../../..
cf create-service newrelic gulab_plan01 nr-newrelic-broker
cf push
cf ssh my-app


