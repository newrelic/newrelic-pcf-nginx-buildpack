#!/bin/bash
cd ../example
ls
cf create-org nr-org
cf target -o "nr-org"
cf create-space nr-space01
cf target -o "nr-org" -s "nr-space01"
cf buildpacks
cf create-service newrelic nrlabs-plan  nr-newrelic-broker
cf bind-service my-app nr-newrelic-broker
cf push
cf logs my-app --recent
cf ssh my-app
cd ../test


