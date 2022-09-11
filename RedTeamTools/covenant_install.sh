#!/bin/bash
# By Cluelessatcoding

# Specify a username or use the default
USER="covenant"

#Install Pre-Requisites
echo "-------------------------------------"
echo "Ensuring Pre-Requisites are installed"
echo "-------------------------------------"
echo ""
apt update && sudo apt install -y --no-install-recommends libc6 libgcc1 libgssapi-krb5-2 libicu66 libssl1.1 libstdc++6 zlib1g

#Create the user account if it does not already exist
if id "${USER}" &>/dev/null; then
        echo "user ${USER} already exist"
    else
        echo "Creating User ${USER}"
		echo ""
        groupadd ${USER}
        useradd --system -g ${USER} -d /home/${USER}/ -m ${USER}
    fi

# Download the dotnet 3.1 SDK under context of the newly created user account
echo "--------------------------"
echo "Downloading dotnet 3.1 SDK"
echo "--------------------------"
echo ""
sudo -u ${USER} -H sh -c 'curl https://download.visualstudio.microsoft.com/download/pr/4fd83694-c9ad-487f-bf26-ef80f3cbfd9e/6ca93b498019311e6f7732717c350811/dotnet-sdk-3.1.422-linux-x64.tar.gz -o /$HOME/dotnet-sdk-3.1.422-linux-x64.tar.gz'

# Extract the dotnet 3.1 SDK under context of the newly created user account
echo "-------------------------"
echo "Extracting dotnet 3.1 SDK"
echo "-------------------------"
echo ""
sudo -u ${USER} -H sh -c 'mkdir -p $HOME/dotnet && tar zxf $HOME/dotnet-sdk-3.1.422-linux-x64.tar.gz -C $HOME/dotnet'

#Clone the Covenant Repository under context of the newly created user account
echo "----------------"
echo "Cloning Covenant"
echo "----------------"
echo ""
sudo -u ${USER} -H sh -c 'cd $HOME; git clone --recurse-submodules https://github.com/cobbr/Covenant'

#Create the Covenant Systemd Service file
cat >> /etc/systemd/system/covenant.service << EOL
[Unit]
Description=Covenant - https://github.com/cobbr/Covenant
After=network.target
[Service]
ExecStart=/home/${USER}/dotnet/dotnet run
WorkingDirectory=/home/${USER}/Covenant/Covenant
SyslogIdentifier=covenant
Environment=DOTNET_ROOT=/home/${USER}/dotnet
User=${USER}
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOL

#Set Covenant to autostart and start the service
echo "-----------------"
echo "Starting Covenant"
echo "-----------------"
sudo systemctl enable covenant
sudo systemctl start covenant
echo ""
echo "------------------------------"
echo ""
echo "Check status of Covenant with:"
echo ""
echo "sudo systemctl status covenant"
echo ""
echo "------------------------------"
