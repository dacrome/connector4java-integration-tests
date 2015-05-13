FROM tomcat:7-jre7

COPY osiam-resource-server $CATALINA_HOME/webapps/osiam-resource-server
COPY osiam-auth-server $CATALINA_HOME/webapps/osiam-auth-server
COPY manager $CATALINA_HOME/webapps/manager
COPY greenmail-webapp $CATALINA_HOME/webapps/greenmail-webapp

RUN sed -i 's/8080/8180/g' $CATALINA_HOME/conf/server.xml

RUN cp -p /usr/share/zoneinfo/${user.timezone} /etc/localtime
RUN echo "${user.timezone}" > /etc/timezone

EXPOSE 8180 11025 11110 8000

CMD [ "catalina.sh", ${debug.pre.command.tomcat} "run"]
