# install_haproxy.sh
This script downloads, extracts and installs the version of OpenSSL 3 and HAPoxy 2.6 specified at the beginning of the script.

Simply make the script executable and run using sudo or as root. 

When the script is done all you need to do is make the final changes to /etc/haproxy/haproxy.conf and start the services. 

If you want to see what is going on when the script runs simply change the log value to standard out. I will add an option for this later. 

![Script Complete](install_haproxy_screenshot.jpg?raw=true "Script Complete")