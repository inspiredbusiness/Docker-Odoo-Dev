FROM inspiredbusiness/docker-odoo:8.0-2015-Q1.0

MAINTAINER Chris White <chris@inspiredbusiness.com.au>

RUN apt-get update \
        && apt-get install -y \
            libswt-gtk-3-java \
            curl \
            openjdk-7-jdk \
        && mkdir -p /opt/dev \
        && mkdir -p /opt/dev/eclipse \        
        && mkdir -p /opt/dev/workspace \
        && touch /opt/dev/workspace/workspace \
        && chown odoo:odoo -R /opt/dev
        #&& /opt/odoo \
        && chown odoo:odoo -R /opt/odoo \
        && echo "odoo ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/odoo \
        && chmod 0440 /etc/sudoers.d/odoo \
        && chown odoo:odoo -R /opt/dev/workspace \
        && chown odoo:odoo -R /opt/odoo/sources \
        && chown odoo:odoo -R /opt/odoo/addiational_addons

USER odoo
WORKDIR /opt/dev
RUN curl http://eclipse.ialto.com/technology/epp/downloads/release/luna/SR1a/eclipse-testing-luna-SR1a-linux-gtk-x86_64.tar.gz | tar -xvz

USER 0
ADD start-odoo.py /opt/odoo/start-odoo.py
RUN mkdir /opt/dev/bin
RUN chmod +x /opt/dev/bin
ADD start-eclipse /opt/dev/bin/start-eclipise
RUN chmod +x /opt/dev/bin/start-eclipise

VOLUME ["/opt/dev/workspace", "/tmp/.X11-unix"]
ENTRYPOINT ["/opt/dev/bin/start-eclipise"]
