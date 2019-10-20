# Eye Network
![alt text](https://img.shields.io/badge/Python-3_only-blue.svg "Python 3 only")

This program will listen to all the connections in your device.

## Features
* You can choose the type of network you want wlan0, eth0, etc ..  
* Filter the type of protocol that you want to TCP or UDP.
* Search for words in packages and take packages and save them in a file.

## Install
```bach
$ git clone https://github.com/HathemAhmed/Eye_network.git
$ cd Eye_network 
$ python3 -m pip install --no-cache-dir -r requirements.txt
$ python3 eye_network.py --help
```

## Options
| Command | Description | Use
| --- | --- | ---
| -m | Model wifi card.| -m wlan0  
| -f | filter types protocols Tcp or Udp| -f tcp
| -w | Search for words in packages | -w password 
| -t | Number timeout for exit for the script| -t 10 
| -H | Acts in the form of hexdump | -H 


## Using
```bach
$ python3 eye_network.py -m wlan0 -f any -t 10 
```
