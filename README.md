# rsyslog-openshift
OpenShift metadata message modification module for rsyslog. This plugin adds information about the OpenShift container to the message.

# Installing rsyslog-openshift
Requires the new (v6+) configuration file format. Tested with rsyslog-7.4.3

1. Apply the patch 'rsyslog-openshift.patch' to the source of rsyslog:

        cd path/to/rsyslog
        patch -p1 -i rsyslog-openshift.patch

1. Copy the mmopenshift directory to rsyslog's plugins directory.
1. Update autotools files:

        cd path/to/rsyslog
        autoreconf

1. Specify `--enable-mmopenshift` when running `configure`
1. make && make install

# Configuration
TODO

# License
Copyright 2014 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
