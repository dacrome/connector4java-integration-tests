#!/bin/sh
set -e

exec /usr/bin/java -Dosiam.addon-self-administration.plugin.osiam.endpoint=http://tomcat:8180 \
     -jar /var/lib/osiam/addon-self-administration.jar --spring.config.location=/var/lib/osiam/application.properties
