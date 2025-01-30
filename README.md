# Network_Intrusion_Detection_System
# Network Intrusion Detection System using Snort

## _What is Snort?_

#### Snort is a network intrusion detection system developed in 1998 by Martin Roesch. Snort, an open source and free software distributed under GNU license, is currently developed by Sourcefire, a company founded by Martin Roesch. 
  

## Features:
- Real-time network traffic analysis
- Rule-based intrusion detection
- Alert generation for suspicious activities
- Logging and reporting of detected intrusions

## Tools & Services Used in this Guide:
- VirtualBox to run the target server.
- kali_linux OS as the Main host.
- Linux server. (Ubuntu server 20.04.4 LTS)
- Snort IDS. (Intrusion Detection System)
- Nmap for performing port Scanning of the target. (Additionally) 
- slowloris for performing DOS attack to target. (Additionally) 
- ssh service to connect to host remotely. 
- apache2 service to run a web app in ubunutu server.


## Guide:

1. First Install VirtualBox (Follow The official instruction from kali docs )
   - https://www.kali.org/docs/virtualization/install-virtualbox-host/
2. Download Ubunutu Server .iso file from the main source 
   - https://ubuntu.com/download/server
3. Set up the Server throw VirtualBox GUI:
   - run VirtualBox
   - Press NEW icon (or Ctrl+N)
   - fill name and the .iso and fellow the instruction.
   - run the new instance and finish the installation steps.
5. install ssh on the ubuntu server (you can skip this step and do the rest mainly in the server command-line)
   - sudo apt install open-ssh
6. install snort IDS  (Intrusion Detection System)  
   - before the installation run "ifconfig" get the network adapter device typename for example "wlan0, or enp0s3", get the inet IP for your server. (you can also run curl ifconfig.me to get the public ip of your server.)
   - sudo apt install snort
   - fill input with server network adapter device type you want to listen on example "enp0s3".
   - fill input with server network IP address and their musk address example "105.103.104.0/24"

7. back to the main OS (kali) and connect to server with ssh service. (you can skip this step and do the rest mainly in the server command-line)
   - ssh username@server_IP_addres
   - enter Password.
8. Check for the configuration file of snort (this is a must before running the IDS) (the location of the config file is /etc/snort/snort.conf) 
   - sudo snort -T -c /etc/snort/snort.conf -i enp0s3    (you will change enp0s3 according to your ifconfig...)
9. run the snort IDS:
   - sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i enp0s3
Congrats all is set.
10. perform some attacks to check for the functionality of your IDS:
   - nmap -sV server_IP (performing PORT scan attack for the server.)
   - slowloris server_IP -s number_of_attacker (performing a DOS attack to the (server Denial of service attack))


# for additional learning you should :


1. **Configuration:**
   - Set up Snort configuration files for rule management.
   - Configure network interfaces for traffic monitoring.
   
2. **Rule Management:**
   - Create custom rules or use predefined rule sets for intrusion detection.
   
3. **Logging and Reporting:**
   - Configure logging options to store detected intrusions.
   - Set up reporting mechanisms for analyzing intrusion patterns.
   
4. **Monitoring and Analysis:**
   - Monitor network traffic using Snort.
   - Analyze packet captures using Wireshark for deeper inspection.
   
5. **Alert Handling:**
   - Set up alert mechanisms for real-time notification of detected intrusions.
   
6. **Maintenance and Updates:**
   - Regularly update Snort rules and software for enhanced security.
   - Perform maintenance tasks to ensure smooth operation of the IDS.

## _Snort Architectural Structure_

#### Snort is made up of different components, and these components work together to identify attacks and generate output. Snort-based IDS systems mainly consist of the following components:

* Packet Decoder
* Preprocessors
* Detection Engine
* Logging and Alerting System
* Output Modules

![image](https://user-images.githubusercontent.com/45822686/118878770-979d4a00-b8f8-11eb-8a56-a4e781a8f931.png)

## _Some Advantages and Disadvantages_

* Snort provides open source and free monitoring for network and computer.
* Any alterations to files and directories on the system can be easily detected and reported.

* When deploying Snort, it’s important to make sure the used rules are relevant and up to date, otherwise the system will be much less efficient
* Although Snort is flexible, it does lack some features found in commercial intrusion detection systems.


## _Cyber Security Solutions Provided by Snort_

#### It has some cyber security solutions provided to us. 
* Snort is to do packet logging and traffic analysis on the network. 
* Snort can detect many attacks and malicious / suspicious software.
* Snort can also be used to perform network/protocol analysis, content searching and matching.

## _Snort Alerts_

#### Alerts are placed in the Alert file in the logging directory. Snort has 6 alert modes. These are fast, full, console, cmg, unsock and none. We applied cmg and console modes. Also, the mode Snort is run in depends on which flags are used with the Snort command.


#### Each alert carry the following information:

*	IP  address of the source
*	IP address of the destination
*	Packet type and useful header information


## _Snort Rules Structure_

The SNORT rule language determines which network traffic should be collected and what should happen when it detects malicious packets. Snort rules are divided into two logical sections, the rule header and the rule options.  The rule header contains the rule's action, protocol, source, destination IP addresses, netmasks,  the source and destination ports information. The rule option section contains alert messages and information on which parts of the packet should be inspected to determine if the rule action should be taken.

```
<Rule Actions> <Protocol> <Source IP Address> <Source Port> <Direction Operator> <Destination IP Address> <Destination port > (rule options)

```

![image](https://user-images.githubusercontent.com/45822686/118878921-c9161580-b8f8-11eb-8787-14ec99898dea.png)



## _Snort Setup_

#### In the installation to be done on the Ubuntu 17.04 in the virtual machine, we first made machine updates and then went to the installation phase. 

## Install Steps

```
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
tar xvzf daq-2.0.7.tar.gz
 cd daq-2.0.7
./configure && make && sudo make install
 
wget https://www.snort.org/downloads/snort/snort-2.9.17.1.tar.gz
tar xvzf snort-2.9.17.1.tar.gz                    
cd snort-2.9.17.1                    
./configure --enable-sourcefire && make && sudo make install 

```


## _Configure Snort_

```
 Commands Used:
 
- snort -V
- ifconfig
- sudo snort -T -i eth0 -c /etc/cnort/snort.conf
- snort -r
- apt-get update
- apt-get install nmap

```

## _Implementing Snort_

Video ----->   https://drive.google.com/file/d/1QJs4uJIRAxkEhf1ORO2tRO5B-qPyQivx/view?usp=sharing

## _Detecting Ping in Snort With Various Snort Alerts Modes_


```
Snort CMG MODE

- Ping 192.168.x.x
- snort -c /etc/snort/snort.conf -q -A cmg

```


```
Snort Console MODE

- ping 192.168.x.x
- snort -c /etc/snort/snort.conf -q -A console
```


```
Creating Rule for Ping Attacks

- sudo gedit /etc/snort/rules/local.rules
- alert  icmp 192.168.x.x any -> $HOME_NET any (msg:”Warning Ping Detected”; sid:1000002; rev:1; classtype:icmp-event;)
- sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3
- ping 192.168.x.x

```



## _Detecting FTP Connection Example_

```
Creating Rule for FTP

- sudo gedit /etc/snort/rules/local.rules
- alert tcp 192.168.x.x any -> $HOME_NET 21 (msg:”FTP connection attempt”; sid:1000002; rev:1;)
- snort -c /etc/snort/snort.conf -q -A console
- ftp 192.168.x.x

```

## _Snort Nmap Scan Detecting Examples_


```
Nmap Scan Detect Without Rule

- snort -c /etc/snort/snort.conf -q -A console
- nmap -sP 192.168.x.x --disable-arp-ping

```


```
Nmap Scan Detect With Rule

- sudo gedit /etc/snort/rules/local.rules
- alert  icmp 192.168.x.x any -> $HOME_NET any (msg:”Nmap Scan Detected”; sid:1000001; rev:1; classtype:icmp-event;)
- snort -c /etc/snort/snort.conf -q -A cmg
- nmap -sP 192.168.x.x --disable-arp-ping

```

```
Nmap TCP Scan Detect With Rule

- sudo gedit /etc/snort/rules/local.rules
- alert  icmp 192.168.x.x any -> $HOME_NET 22 (msg:”Nmap TCP Scan Detected”; sid:10000005; rev:2; classtype:tcp-event;)
- snort -c /etc/snort/snort.conf -q -A console
- nmap -sT -p22 192.168.x.x

```


This experiment was part of The Learning tasks during The CodeAlpha internship.
