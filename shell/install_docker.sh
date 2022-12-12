#!/bin/bash

# if os is not ubuntu or debian, exit
if ! grep -q "Ubuntu" /etc/issue && ! grep -q "Debian" /etc/issue;
  then
    echo "This script only works on Ubuntu or Debian"
    exit 1
fi

# install docker
sudo apt-get -y install ca-certificates curl wget gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
# check if ubuntu or debian
if grep -q "Ubuntu" /etc/issue; 
then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg  
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
else
  curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg    
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null  
fi
sudo chmod a+r /etc/apt/keyrings/docker.gpg  
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin
#check compose version and install compose
VERSION=$(curl --silent https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K.*\d') %%
DESTINATION=/usr/local/bin/docker-compose
sudo curl -L https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-$(uname -s)-$(uname -m) -o $DESTINATION &&
sudo chmod 755 $DESTINATION
sudo usermod -aG docker $USER
sudo systemctl enable docker