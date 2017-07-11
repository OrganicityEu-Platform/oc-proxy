# OC proxy

## Install

```
cd /opt
git clone https://github.com/OrganicityEu-Platform/oc-proxy.git
cd oc-proxy
cp config.template.js config.js
# Configure the application (chain, client_id and client_secret, application_endpoint and nofification_proxy)
npm install
```

Link startup script and the log rotate (Like this, the script are kept up to date with git changes):

```
ln -s /opt/oc-proxy/scripts/etc/init.d/oc-proxy /etc/init.d/oc-proxy
ln -s /opt/oc-proxy/scripts/etc/logrotate.d/oc-proxy /etc/logrotate.d/oc-proxy
```

## Run manually

```
/etc/init.d/oc-proxy start
/etc/init.d/oc-proxy stop
/etc/init.d/oc-proxy restart
/etc/init.d/oc-proxy status
```

## Autostart

### Ubuntu (14.04)

Add:

```
sudo update-rc.d oc-proxy defaults
```

Enable/Disable:

```
sudo update-rc.d oc-proxy enable
sudo update-rc.d oc-proxy disable
```

Remove:

```
sudo update-rc.d -f oc-proxy remove
```

### Cent OS

Enable/Disbale

```
chkconfig oc-proxy on
chkconfig oc-proxy off
```

Verify:

```
chkconfig --list oc-proxy
```

## Test logrotate

```
logrotate --force /etc/logrotate.d/oc-proxy
```
