# OC proxy

## Install

```
cd /opt
git clone git@github.com:OrganicityEu-Platform/oc-proxy.git
cd oc-proxy
cp config.template.js config.js
# Configure the application_endpoint
npm install
```

Copy script:

```
cp scripts/etc/init.d/oc-proxy /etc/init.d/
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

