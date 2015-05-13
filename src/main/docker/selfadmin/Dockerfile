FROM java:openjdk-8-jre

RUN mkdir -p /var/lib/osiam && \
    cp -p /usr/share/zoneinfo/${user.timezone} /etc/localtime && \
    echo "${user.timezone}" > /etc/timezone

COPY application.properties /var/lib/osiam/application.properties
COPY addon-self-administration-${version.osiam.addon-self-administration}.jar /var/lib/osiam/addon-self-administration.jar
COPY addon-self-administration /var/lib/osiam/addon-self-administration/
COPY addon-self-administration-plugin-example.jar /install/plugin-example.jar

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
COPY entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod +x /usr/local/bin/docker-entrypoint

EXPOSE 50513
