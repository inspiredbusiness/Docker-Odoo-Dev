Odoo Eclipise Dev image
-----

Debug Odoo 7.0, 8.0, 9.0a and Odoo modules in eclipse.


Start Docker image
-------
sudo docker run --name="pg" -d xcgd/postgresql

sudo docker run --rm -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -p 8069:8069 --link pg:db inspiredbusiness/odoo-dev

After eclipse loads
--------

1) Import existing project in folder "/opt/odoo"

2) Create new PyDev debug profile

Debug Profile Name: Odoo

Project: Odoo

Main Module: ${workspace_loc:Odoo/start-odoo.py}<br />
Arugments: -c /opt/odoo/etc/odoo.conf



TODO: Create a default workspace with project and debug profiles pre-configured

Enjoy :)

Don't forget to mount volumes for your oddo addons and the eclipse workspace

/opt/dev/workspace
/opt/odoo/additional_addons

Based off: xcgd/postgresql
