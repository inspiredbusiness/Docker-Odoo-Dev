FROM inspiredbusiness/docker-odoo:8.0-2015-Q1.0

MAINTAINER Chris White <chris@inspiredbusiness.com.au>

RUN apt-get update \
        && apt-get install -y \
            libswt-gtk-3-java \
            curl \
            openjdk-7-jdk \
            sudo \
        && mkdir -p /opt/odoo-dev \
        && chown odoo:odoo -R /opt/odoo-dev \
        && mkdir -p /opt/odoo \
        && chown odoo:odoo -R /opt/odoo \
        && echo "odoo ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/odoo \
        && chmod 0440 /etc/sudoers.d/odoo

USER odoo
WORKDIR /opt/odoo-dev
RUN curl http://eclipse.ialto.com/technology/epp/downloads/release/luna/SR2/eclipse-standard-luna-SR2-linux-gtk-x86_64.tar.gz | tar -xvz

WORKDIR /opt/odoo-dev/eclipse

RUN ./eclipse \
	-application org.eclipse.equinox.p2.director \
	-repository http://pydev.org/updates \
	-installIUs org.python.pydev.feature.feature.group \
	-noSplash \
	-clean \
	-purgeHistory

CMD sudo mkdir /opt/odoo-dev/bin
ADD start-debug-odoo.py /opt/odoo-dev/bin/start-debug-odoo.py
ADD start-eclipse /opt/odoo-dev/bin/start-eclipse

USER 0
CMD chmod +x /opt/odoo-dev/bin/start-eclipse

USER odoo
CMD bash /opt/odoo-dev/bin/start-eclipse
VOLUME ["/tmp/.X11-unix", "/opt/odoo-dev/workspace"]
ENTRYPOINT []
