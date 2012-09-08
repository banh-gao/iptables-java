iptables-java - Java library for iptables
by Daniel Zozin <zdenial@gmx.com>

This library provides a communication interface to the iptables firewall, to linux netfilter logger and connection tracker.

The rule manager allows to parse, generate and apply the iptables rules to the local linux machine.
The log tracker provides a java notification system for low level netfilter log events.
The connection tracker notifies for established connections and connection state changes.

===============================================================================================================================================

INSTALLATION FROM SOURCES

In order to compile the library, you need the libnetfilter_log and libnetfilter_conntrack library header files.
You can find them at http://www.netfilter.org/

On Debian or derived distribution just run:
sudo apt-get install libnetfilter-log-dev libnetfilter-conntrack-dev

The compilation is executed through an ant script, set the jnidir param to the directory path where your virtual machine jni header files are stored, go into the directory of build.xml and run:
ant build -Djnidir=VMHeadersDir

The ant script will generate the compiled library files and also the jar archive.

===============================================================================================================================================

INSTALLATION FROM BINARY

This library was made available as a binary package for the debian and derived distributions, this package also include the documentation.
To install the package execute:

dpkg -i libiptables-java_arch.deb 

The java library will be installed in the /usr/share/java directory while the documentation is in /usr/share/doc

===============================================================================================================================================

USAGE

To use the library you must include the jar archive in your project and place the binary file in a system library directory.

In order to access to the netfilter functionalities the library must be authorized with the CAP_NET_ADMIN posix capability.
You can run the application as a privileged user or you can assign that capability directly to the java executable with something like:

setcap 'CAP_NET_ADMIN+eip' `readlink -f /usr/bin/java`

however note that this will assign the capability to any java program using the same java executable.

In order to receive log events from the firewall, an nflog action must be set as an iptables rule, the prefix setted with the rule allows to match a log event with a specific rule.
For example to append a logging rule to the INPUT chain of the filter table use:

iptables -A INPUT -j NFLOG --nflog-prefix INDROPPED

The log listeners will be notified when this rule is reached and the log prefix corresponds to INDROPPED.