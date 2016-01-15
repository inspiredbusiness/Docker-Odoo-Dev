FROM inspiredbusiness/docker-odoo:9.0-latest

MAINTAINER Chris White <chris@inspiredbusiness.com.au>

RUN apt-get update \
        && apt-get install -y \
            libswt-gtk-3-java \
            curl \
            openjdk-7-jdk \
        && mkdir -p /opt/odoo-dev \
        && chown odoo:odoo -R /opt/odoo-dev \
        && mkdir -p /opt/odoo \
        && chown odoo:odoo -R /opt/odoo

USER odoo
WORKDIR /opt/odoo-dev
RUN curl http://eclipse.ialto.com/technology/epp/downloads/release/mars/R/eclipse-java-mars-R-linux-gtk-x86_64.tar.gz | tar -xvz

WORKDIR /opt/odoo-dev/eclipse
RUN ./eclipse \
	-application org.eclipse.equinox.p2.director \
	-repository https://dl.bintray.com/fabioz/pydev/4.5.1/ \
	-installIUs org.python.pydev.feature.feature.group \
	-noSplash \
	-clean \
	-purgeHistory

USER 0
RUN mkdir -p /opt/odoo-dev/bin
RUN mkdir -p /opt/odoo-dev/workspace
ADD start-debug-odoo.py /opt/odoo-dev/bin/start-debug-odoo.py
RUN chown odoo /opt/odoo-dev/bin/start-debug-odoo.py
ADD start-eclipse /opt/odoo-dev/bin/start-eclipse
RUN chmod +x /opt/odoo-dev/bin/start-eclipse

VOLUME /opt/odoo-dev/workspace

ENTRYPOINT ["/opt/odoo-dev/bin/start-eclipse"]
