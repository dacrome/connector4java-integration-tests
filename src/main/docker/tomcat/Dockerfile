FROM tomcat:8-jre8

RUN mkdir -p /var/lib/osiam
COPY osiam-resource-server $CATALINA_HOME/webapps/osiam-resource-server
COPY auth-server-${version.osiam.auth-server}.war $CATALINA_HOME/webapps/osiam-auth-server.war
# COPY osiam-auth-server.xml $CATALINA_HOME/conf/Catalina/localhost/
COPY addon-self-administration-${version.osiam.addon-self-administration}.war /var/lib/osiam/addon-self-administration.war
COPY addon-self-administration.properties /var/lib/osiam/
COPY addon-self-administration /var/lib/osiam/addon-self-administration
COPY addon-self-administration.xml $CATALINA_HOME/conf/Catalina/localhost/
COPY addon-self-administration-plugin-example.jar /install/plugin-example.jar
COPY selfadminexample.properties /install/
COPY manager $CATALINA_HOME/webapps/manager

ADD http://central.maven.org/maven2/com/icegreen/greenmail-webapp/1.4.0/greenmail-webapp-1.4.0.war $CATALINA_HOME/webapps/

RUN cat /install/selfadminexample.properties >> $CATALINA_HOME/conf/catalina.properties
RUN sed -i 's/8080/8180/g' $CATALINA_HOME/conf/server.xml
RUN cp -p /usr/share/zoneinfo/${user.timezone} /etc/localtime
RUN echo "${user.timezone}" > /etc/timezone

EXPOSE 8180
