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

RUN curl -L https://download.jetbrains.com/python/pycharm-community-5.0.3.tar.gz | tar xvz
WORKDIR /opt/odoo-dev/pycharm-community-5.0.3

USER 0
RUN mkdir -p /opt/odoo-dev/bin
RUN mkdir -p /var/lib/odoo/PycharmProjects
ADD start-debug-odoo.py /opt/odoo-dev/bin/start-debug-odoo.py
RUN chown odoo /opt/odoo-dev/bin/start-debug-odoo.py
ADD start-pycharm /opt/odoo-dev/bin/start-pycharm
RUN chmod +x /opt/odoo-dev/bin/start-pycharm

VOLUME ["/var/lib/odoo", "/opt/odoo-dev/filestore"]

ENTRYPOINT ["/opt/odoo-dev/bin/start-pycharm"]
