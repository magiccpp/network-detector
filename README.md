China 
1. Raspberry pi 4/5 with at least 4G RAM, this is the primary router
2. A USB to RJ45 adapter to make the RPI as a router.
3. Another Raspberry pi 4/5 or an old laptop with at least 8G RAM/256G SSD, this is the network detector server. 
4. A home switch - for connecting your own devices with wired network
5. A home WIFI router - for connecting your WIFI devices at home

The guide includes 2 parts:
- Fanqiang router
- Traffic detector

# Setup the Fanqiang router
After this step, you can access the websites out of China. You will use China telecom's DNS server for domestic websites and Google's DNS server for international websites, this would give you much better surfing experience in China~
## Setup dnscrypt-proxy
The dnscrypt proxy send the encrypted DNS queries and it cannot be kidnapped.
install dnscrypt-proxy, and set it up
```
sudo apt update
sudo apt install -y dnscrypt-proxy

sudo nano /etc/dnscrypt-proxy/dnscrypt-proxy.toml
```

add below lines into the file
```
listen_addresses = ['127.0.0.1:5454']
bootstrap_resolvers = ['9.9.9.11:53', '8.8.8.8:53']
```

Then start dnscrypt-proxy
```
sudo systemctl enable dnscrypt-proxy
sudo systemctl restart dnscrypt-proxy
sudo systemctl status dnscrypt-proxy
```

Then test dnscrypt-proxy
```
dig @127.0.0.1 -p 5454 google.com
```

## Setup dnsmasq
editing /etc/dnsmasq.conf, set the DHCP range, it is the IP range will be assigned to your wired devices like computer: i.e.
```
dhcp-range=192.168.4.50,192.168.4.60
```
then 
```
cp router/chn_domains.txt /etc/dnsmasq.d
```

## Set the route for Chinese DNS server
sudo nmcli connection modify eth0 +ipv4.routes "116.228.111.118/32 <your Chinese gateway IP address>"

## Setup the trace capturing service
```
sudo cp router/capture_network.sh /usr/local/bin/capture_network.sh
```

sudo vim /etc/systemd/system/capture_network.service
```
[Unit]
Description=Network Capture with tcpdump on tun0, eth0, eth1
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/capture_network.sh
ExecStop=/bin/kill -SIGINT $MAINPID
Restart=on-failure
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Start up the trace capturing service
```
sudo systemctl daemon-reload
sudo systemctl enable capture_network.service
sudo systemctl start capture_network.service
```



# Setup the detector
## Make sure your laptop doesn't sleep (optional)
if you are using an old laptop, need to make sure the laptop does not sleep when the lid is closed.
sudo nano /etc/systemd/logind.conf
#HandleLidSwitch=suspend
HandleLidSwitch=ignore
sudo systemctl restart systemd-logind

you can now close the lip of the laptop


## Install docker
see:
https://docs.docker.com/engine/install/ubuntu/#installation-methods

## Install pyenv (devloper only)
install pyenv:
sudo apt update
sudo apt install -y \
  make build-essential libssl-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev curl \
  libncursesw5-dev xz-utils tk-dev libxml2-dev \
  libxmlsec1-dev libffi-dev liblzma-dev git


git clone https://github.com/pyenv/pyenv.git ~/.pyenv

add into ~/.bashrc
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"

source ~/.bashrc  

pyenv install 3.11.13
pyenv global 3.11.13


## Check if you can see the network traffic
Since you have already enabled the port mirroring, you should be able to see all the network traffic go through the primary router on the detector. try below

