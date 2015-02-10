FROM inspiredbusiness/docker-odoo:8.0-2015-Q1.0

MAINTAINER Chris White <chris@inspiredbusiness.com.au>

RUN apt-get update
        && apt-get install -y \
            libswt-gtk-3-java \
            curl \
            openjdk-7-jdk \
        && mkdir -p /opt/dev \
        && chown odoo:odoo -R /opt/dev

USER odoo
RUN mkdir -p /opt/dev/eclipse \
        && mkdir -p /opt/dev/workspace

WORKDIR /opt/dev
RUN curl http://eclipse.ialto.com/technology/epp/downloads/release/luna/SR1/eclipse-java-luna-SR1-linux-gtk-x86_64.tar.gz | tar -xvz

WORKDIR /opt/dev/eclipse

#RUN ./eclipse \
#	-application org.eclipse.equinox.p2.director \
#	-repository http://pydev.org/updates \
#	-installIUs org.python.pydev.feature.feature.group \
#	-noSplash \
#	-clean \
#	-purgeHistory

RUN echo "<?xml version='1.0' encoding='UTF-8'?><projectDescription><name>Odoo</name><comment /><projects /><buildSpec><buildCommand><name>org.python.pydev.PyDevBuilder</name><arguments /></buildCommand></buildSpec><natures><nature>org.python.pydev.pythonNature</nature></natures></projectDescription>" > /opt/odoo/.project

USER 0
RUN touch /opt/dev/workspace/workspace \
        && chown odoo:odoo -R /opt/dev \
        && chown odoo:odoo -R /opt/dev/workspace \
        && chown odoo:odoo -R /opt/odoo

RUN echo "odoo ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/odoo
RUN chmod 0440 /etc/sudoers.d/odoo

USER odoo
ADD start-odoo.py /opt/odoo/start-odoo.py
CMD sudo mkdir /opt/dev/bin
CMD sudo chmod +x /opt/dev/bin
ADD start-eclipse /opt/dev/bin/start-eclipise
CMD sudo chmod +x /opt/dev/bin/start-eclipise

USER 0
CMD chmod +x /opt/dev/bin/start-eclipise

USER odoo
CMD bash /opt/dev/bin/start-eclipise

VOLUME ["/opt/dev/workspace", "/tmp/.X11-unix"]
ENTRYPOINT []
