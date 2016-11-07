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

## Run

```
/etc/init.d/oc-proxy start
/etc/init.d/oc-proxy stop
/etc/init.d/oc-proxy restart
/etc/init.d/oc-proxy status
```

