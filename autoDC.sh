#!/usr/bin/bash

# Author: Adrián Luján Muñoz (aka clhore)

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

trap ctrl_c INT

function ctrl_c(){
	echo -e "\n${yellowColour}[*]${endColour}${grayColour}Saliendo${endColour}"
	tput cnorm; exit 0
}

function helpPanel(){
	echo -e "help panel"
	exit 0
}

function systemCheck(){
    	systemUser=$(hostnamectl | grep 'Operating System:' | xargs | awk '{print $3}')
	if [ "$systemUser" == "Ubuntu" ]; then return 0; fi; return 1
}

function config(){
	local pcName=$(whiptail --inputbox "Introduce el nuebo nombre del equipo (Ej: smb-dc.somebooks.lan):" 8 78 --title "autoDC - by Adrián Luján Muñoz" 3>&1 1>&2 2>&3)
	local pcIp=$(whiptail --inputbox "Introduce la ip fija ha asiganr a su servidor (Ej: 192.168.1.111/24):" 8 78 --title "autoDC - by Adrián Luján Muñoz" 3>&1 1>&2 2>&3)
	local gatewayIp=$(whiptail --inputbox "Introduce la ip gateway (Ej: 192.168.1.1):" 8 78 --title "autoDC - by Adrián Luján Muñoz" 3>&1 1>&2 2>&3)
	local dns=$(whiptail --inputbox "Introduce los DNS que deseas usar (Ej: 8.8.8.8, 8.8.4.4):" 8 78 --title "autoDC - by Adrián Luján Muñoz" 3>&1 1>&2 2>&3)
	echo -en "${grayColour}:: Asignando la ip fija $pcIp${endColour}"
	local domainPC1=$(echo $pcName | awk -F '.' '{print $2}')
	local domainPC2=$(echo $pcName | awk -F '.' '{print $3}')
	local domainPC=$(echo "${domainPC1}.${domainPC2}")
	mv /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.save; echo -e "
# This is the network config by 'Adrián Luján Muñoz (aka clhore)'
network:
  ethernets:
        ens33:
            dhcp4: false
            addresses: [${pcIp}]
            gateway4: $gatewayIp
            nameservers:
                addresses: [${dns}]
                search: [${domainPC}]
  version: 2
" > /etc/netplan/00-installer-config.yaml

	sudo netplan apply &> /dev/null

	if [ $? -eq 0 ]; then
		echo -e " ${greenColour}listo${endColour}"
        	echo -en "${grayColour}:: Asignando los dns $dns${endColour}"; sleep 0.5; echo -e " ${greenColour}listo${endColour}"
		echo -en "${grayColour}:: Asignando la ip gateway ${gatewayIp}${endColour}"; sleep 0.5; echo -e " ${greenColour}listo${endColour}"
		echo -en "${grayColour}:: Anadiendo hostname[$pcName] y ip al /etc/hosts${endColour}"

		local namePc=$(echo $pcName | awk -F '.' '{print $1}')
		hostnamectl set-hostname $namePc &>/dev/null; sleep 1
		local ip=$(echo $pcIp | sed 's/\(.*\)\//\1 /' | awk '{print $1}')

		mv /etc/hosts /etc/hosts.save; echo -e "
# autoDC by 'Adrián Luján Muñoz (aka clhore)'
127.0.0.1 localhost
127.0.1.1 localhost
${ip} ${pcName} ${namePc}

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
" > /etc/hosts

		echo -e " ${greenColour}listo${endColour}"; echo -e "${ip} ${pcName}" > .tmp 2>/dev/null
	else
		echo -e " ${redColour}Error${endColour}"
		ctrl_c
	fi
}

function checkInternet(){
	local list=(google.com elmundo.es youtube.com github.com)

	echo -en "${grayColour}:: Comprovando la conexion a internet${endColour}"

	for i in "${list[@]}"; do
		ping -c 1 $i &>/dev/null
		if [ $? -eq 0 ]; then let codeCheck+=1; fi
	done

	sleep 0.5; echo " ${codeCheck}/4"; sleep 1
}

function ntpConfig(){
	whiptail --title "autoDC - by Adrián Luján Muñoz" --yesno "Desea configurar un servidor ntp" 8 40

	if [ $? -eq 0  ]; then
		timeZone=$(
        		whiptail --title "dcControl - by Adrián Luján Muñoz" --menu "Seleccione su zona horaria:" 16 40 8 \
                		"1)" "Europe/Madrid" \
                		"2)" "Europe/London" \
                		"3)" "America/Indiana/Winamac" \
                		"4)" "America/Puerto_Rico" \
                		"5)" "America/Tijuana" \
                		"6)" "America/Panama" \
                		"7)" "America/Rosario" \
                		"8)" "America/Mexico_City" 3>&2 2>&1 1>&3
		)

		if [ "$timeZone" != "" ]; then
        		case $timeZone in
                		"1)") declare -r timeZone="Europe/Madrid";; "2)") declare -r timeZone="Europe/London";;
                		"3)") declare -r timeZone="America/Indiana/Winamac";; "4)") declare -r timeZone="America/Puerto_Rico";;
                		"5)") declare -r timeZone="America/Tijuana";; "6)") declare -r timeZone="America/Panama";;
                		"7)") declare -r timeZone="America/Rosario";; "8)") declare -r timeZone="America/Mexico_City";;
        		esac
		else return 0; fi

		local ntpServer=$(whiptail --inputbox "Introduce el servidor ntp o introduzac defauld par no realizar cambios (Ej: hora.rediris.es):" 8 78 --title "autoDC - by Adrián Luján Muñoz" 3>&1 1>&2 2>&3)
		if [[ "${ntpServer}" != "defauld" && "${ntpServer}" != "" ]]; then
			echo -en "${grayColour}:: Asignando zona horaria $timeZone${endColour}"
			timedatectl set-timezone "${timeZone}" &>/dev/null; timedatectl set-timezone "${timeZone}" &>/dev/null

			if [ $? -eq 0 ]; then timedatectl set-ntp no &>/dev/null; echo -e " ${greenColour}listo${endColour}"; else echo -e " ${redColour}error${endColour}"; return 1; fi

			echo -en "${grayColour}:: Instalando paquete ntp ntpdate${endColour}"
			apt update -y &>/dev/null; apt install ntp ntpdate -y &>/dev/null

			if [ $? -eq 0 ]; then echo -e " ${greenColour}listo${endColour}"; else echo -e " ${redColour}error${endColour}"; return 1; fi

			echo -en "${grayColour}:: Introduciendo $ntpServer en /etc/ntp.conf${endColour}"
			cp /etc/ntp.conf /etc/ntp.conf.save; sleep 0.5; echo -e "server ${ntpServer}" >> /etc/ntp.conf 2>/dev/null

			if [ $? -eq 0 ]; then echo -e " ${greenColour}listo${endColour}"; else echo -e " ${redColour}error${endColour}"; mv /etc/ntp.conf.save /etc/ntp.conf; return 1; fi

			echo -en "${grayColour}:: Sincronizando el equipo al servidor ntp${endColour}"
			systemctl stop ntp &>/dev/null; ntpdate -B $ntpServer &>/dev/null

			if [ $? -eq 1 ]; then
				 apt remove --purge ntpdate -y &>/dev/null; apt install ntpdate -y &>/dev/null
				 ntpdate -B $ntpServer &>/dev/null
			fi; systemctl start ntp &>/dev/null; if [ $? -eq 1 ]; then echo -e " ${redColour}error${endColour}"; return 1; fi; echo -e " ${greenColour}listo${endColour}"
		fi
	fi
}

function dependencies(){
    	sleep 2;local dependencies=(ufw samba winbind smbclient attr acl); local errorCode=()

	echo -en "${grayColour}:: Actualizando el sistema${endColour}"; sleep 1

	local list=(update upgrade dist-upgrade update)
	local count=25

    	{
		for i in {0..4..1};do
            	apt "${list[$1]}" &>/dev/null; sleep 0.2
            	echo $count; let count+=25; sleep 2
        	done
    	} | whiptail --title "autoDC - by Adrián Luján Muñoz" \
                     --gauge "Espera mientras actualizamos OS..." 5 40 0

	echo -e " ${greenColour}Listo${endColour}"

	for program in "${dependencies[@]}"; do
		echo -ne "${yellowColour}::${endColour}${blueColour} Instalando herramienta${endColour}${purpleColour} $program${endColour} "
		sudo apt install $program -y &>/dev/null

		if [ $? -eq 0 ]; then
			errorCode+=(0)
			echo -e "${greenColour}(V)${endColour}"
		else
			errorCode+=($program)
			echo -e "${redColour}(X)${endColour}"
		fi
	done

	echo -e "${yellowColour}::${endColour}${blueColour} Iniciando proceso de intalacion${endColour} ${purpleColour}kerberos${endColour}"; sleep 1
	sudo apt-get install krb5-config; sleep 4

	if [ $? -eq 0 ]; then errorCode+=(0); else errorCode+=(krb5-config); fi

	clear; for i in "${errorCode[@]}"; do if [ "$i" != "0" ]; then echo -e "${redColour}Error instalacion${endColour} $i [sudo apt-get install $i]"; exit 1; fi; done
}

function checkSamba(){
	local msg=("Servico DC" "Create USERS"); samba-tool user delete user-prueba &>/dev/null
	# local list=("domain level show | grep '2008 R2'" "user create user-prueba P@ssw0rd | grep 'created successfully'") ss -tulpn | grep :53 | grep dns

	echo -en "${grayColour}:: ${msg[0]}${endColour}"
	samba-tool domain level show | grep '2008 R2' &>/dev/null

	if [ $? -eq 0 ]; then sleep 0.5; echo -e " ${greenColour}listo${endColour}"; sleep 0.5; else echo -e " ${redColour}error${endColour}"; fi

	echo -en "${grayColour}:: ${msg[1]}${endColour}"
        samba-tool user create user-prueba P@ssw0rd | grep 'created successfully' &>/dev/null

        if [ $? -eq 0 ]; then sleep 0.5; echo -e " ${greenColour}listo${endColour}"; sleep 0.5; else echo -e " ${redColour}error${endColour}"; fi

	samba-tool user delete user-prueba &>/dev/null
}

function toDC(){
	sleep 1; ntpConfig; dependencies
	echo -e "${grayColour}:: Iniciando la configuracion de samba${endColour}"
	sleep 1; sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old &>/dev/null; sudo samba-tool domain provision --use-rfc2307 --interactive; sleep 1; sudo cp /var/lib/samba/private/krb5.conf /etc &>/dev/null; clear
	echo -en "${grayColour}:: Configuracion de samba${endColour}"; sleep 0.5; echo -e " ${greenColour}listo${endColour}";
	echo -en "${grayColour}:: Deteniendo servicios${endColour}"; sleep 0.5;

	local list=("stop smbd nmbd winbind systemd-resolved" "disable smbd nmbd winbind systemd-resolved" "unmask samba-ad-dc")
	local count=25

	{
                for i in {0..3..1};do
                systemctl "${list[$1]}" &>/dev/null; sleep 0.2
                echo $count; let count+=50; sleep 2
                done
        } | whiptail --title "autoDC - by Adrián Luján Muñoz" \
                     --gauge "Espera mientras configuramos los servicios..." 5 40 0

	echo -e " ${greenColour}listo${endColour}"; systemctl unmask samba-ad-dc &>/dev/null

	echo -en "${grayColour}:: Creando fichero /etc/resolv.conf${endColour}"; rm /etc/resolv.conf &>/dev/null
	echo -e "nameserver 127.0.0.1" > /etc/resolv.conf 2>/dev/null

	if [ $? -eq 0 ]; then sleep 0.5; echo -e " ${greenColour}listo${endColour}"; sleep 0.5; else echo -e " ${redColour}error${endColour}"; ctrl_c; fi

	echo -en "${grayColour}:: Start samba-ad-dc${endColour}"; systemctl stop samba-ad-dc &>/dev/null
        systemctl start samba-ad-dc &>/dev/null

        if [ $? -eq 0 ]; then sleep 0.5; echo -e " ${greenColour}listo${endColour}"; sleep 0.5; else echo -e " ${redColour}error${endColour}"; fi

        echo -en "${grayColour}:: Enable samba-ad-dc${endColour}"; sleep 0.5
        systemctl enable samba-ad-dc &>/dev/null

        if [ $? -eq 0 ]; then sleep 0.5; echo -e " ${greenColour}listo${endColour}"; sleep 0.5; else echo -e " ${redColour}error${endColour}"; fi

	ss -tulpn | grep :53 | grep 'systemd-resolved' &>/dev/null

	if [ $? -eq 0 ]; then
		echo -en "${grayColour}:: Matado procesos en conflicto${endColour}"; sleep 0.5
		systemctl stop systemd-resolved; systemctl disable systemd-resolved
		local ip=$(cat .tmp | awk '{print $1}'); local pcDomain=$(cat .tmp | awk '{print $2}')
		unlink /etc/resolv.conf &>/dev/null; echo -e "nameserver ${ip}\nsearch ${pcDomain}" > /etc/resolv.conf 2>/dev/null; echo -e " ${greenColour}listo${endColour}"
	fi

	local d1=$(echo "${pcDomain}" | awk -F '.' '{print $2}'); local d2=$(echo "${pcDomain}" | awk -F '.' '{print $3}'); local domain=$(echo "${d1}.${d2}")

	host -t SRV _kerberos.udp${domain} | grep '(NXDOMAIN)' &>/dev/null

	if [ $? -eq 0 ]; then
		echo -en "${grayColour}:: Reparando kerberos${endColour}"; sleep 0.5
		apt install krb5-user &>/dev/null; kinit Administrator; klist
		local pid=$(sudo ps -aux | grep samba | grep Ss | xargs | awk '{print $2}'); kill $pid &>/dev/null
		local list=("mask smbd nmbd winbind" "disable smbd nmbd winbind" "stop smbd nmbd winbind" "unmask samba-ad-dc" "start samba-ad-dc" "enable samba-ad-dc")
        	for cmd in "${list[@]}"; do systemctl $cmd $>/dev/null; done; echo -e " ${greenColour}listo${endColour}"
	fi

	local listPorts=(1:65535/tcp 1:65535/udp); ufw enable &>/dev/null

	for port in "${listPorts[@]}"; do ufw allow $port &>/dev/null; done; rm .tmp 2>/dev/null; checkSamba
	echo -e "${grayColour}:: El equipo se${endColour} ${redColour}reiniciara en 4s${endColour}"; sleep 4; reboot
}

function main(){
	clear; config; declare -i codeCheck=0
	while :
	do
		if [ $codeCheck -eq 0 ] || [ $codeCheck -le 2 ]; then checkInternet; else toDC; fi
	done
}

# Check executed use root user
if [ "$(id -u)" == "0" ]; then
	whiptail --title "autoDC - by Adrián Luján Muñoz" --yesno "Ejecutamos el programa de intsalcion" 8 40

	if [ $? -eq 1  ]; then ctrl_c; fi

	whiptail --title "autoDC - by Adrián Luján Muñoz" --msgbox "Este es un script que automatiza la creacion de un DC.\nIntalacion y configuracion basica para un DC." 8 78
	whiptail --title "autoDC - by Adrián Luján Muñoz" --msgbox "Si desea cancelar la intalacion en algun momento, le recomendamos encarecidamente que presione Ctrl + C." 8 78

    	systemCheck; if [ $? -eq 0 ]; then main; fi
else
	echo -e "${redColour}Ejecute el script como root${endColour}"
fi
