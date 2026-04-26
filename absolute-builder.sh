#!/bin/bash

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     CYBER FRAMEWORK - AUTO INSTALLER       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"

# 1. Prérequis Système & Outils de Hacking
echo -e "\n${GREEN}[+] 1/4 Installation de l'Arsenal Système...${NC}"
sudo apt update -y
sudo apt install -y python3 python3-venv python3-pip git curl wget \
    nmap whatweb gobuster hydra netcat-traditional \
    openvpn lynx john hashcat # Ajout du VPN, Lynx et outils de crack

# Installation de Nuclei (Scanner Web moderne)
if ! command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}[*] Installation de Nuclei...${NC}"
    sudo apt install -y nuclei || echo "Nuclei devra être installé via Go si absent des dépôts."
fi

# 2. Base de données d'Exploits
if [ ! -d "/opt/exploitdb" ]; then
    echo -e "${GREEN}[+] 2/4 Clonage de Exploit-DB (Searchsploit)...${NC}"
    sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
else
    echo -e "${CYAN}[*] 2/4 Exploit-DB est déjà opérationnel.${NC}"
fi

# 3. Préparation du Workspace
echo -e "${GREEN}[+] 3/4 Configuration du Workspace...${NC}"
WORKDIR=~/cyber-workspace
mkdir -p $WORKDIR/rapports
cp framework.py $WORKDIR/ 2>/dev/null
cp common.txt $WORKDIR/ 2>/dev/null || echo -e "admin\nroot\npassword\nsecret\nmememe" > $WORKDIR/common.txt

# 4. Le Cerveau Python (VENV)
echo -e "${GREEN}[+] 4/4 Installation des modules Python...${NC}"
cd $WORKDIR
if [ ! -d "env" ]; then
    python3 -m venv env
fi
env/bin/pip install python-nmap rich colorama requests --break-system-packages 2>/dev/null || env/bin/pip install python-nmap rich colorama requests

# 5. Création du raccourci global
echo -e "${GREEN}[+] Création du lanceur 'cyber'...${NC}"
echo '#!/bin/bash' > cyber
echo "cd $WORKDIR && sudo $WORKDIR/env/bin/python $WORKDIR/framework.py \"\$@\"" >> cyber
chmod +x cyber
sudo mv cyber /usr/local/bin/cyber

echo -e "\n${CYAN}[*] DÉPLOIEMENT TERMINÉ !${NC}"
echo -e "-> Tape ${GREEN}cyber${NC} de n'importe où pour lancer ton framework."