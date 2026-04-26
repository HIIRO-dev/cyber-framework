#!/bin/bash

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     CYBER FRAMEWORK - AUTO INSTALLER       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"

# 1. Prérequis Système & Outils de Hacking
echo -e "\n${GREEN}[+] 1/5 Installation de l'Arsenal Système...${NC}"
sudo apt update -y
sudo apt install -y python3 python3-venv python3-pip git curl wget \
    nmap whatweb gobuster hydra netcat-traditional \
    openvpn lynx john hashcat

# Installation de Nuclei
if ! command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}[*] Installation de Nuclei...${NC}"
    sudo apt install -y nuclei || echo "Nuclei devra être installé via Go si absent."
fi

# 2. Base de données d'Exploits
if [ ! -d "/opt/exploitdb" ]; then
    echo -e "${GREEN}[+] 2/5 Clonage de Exploit-DB (Searchsploit)...${NC}"
    sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
else
    echo -e "${CYAN}[*] 2/5 Exploit-DB est déjà opérationnel.${NC}"
fi

# 3. Préparation du Workspace
echo -e "${GREEN}[+] 3/5 Configuration du Workspace...${NC}"
WORKDIR=~/cyber-workspace
REPO_DIR=$(pwd) # On sauvegarde l'emplacement du dossier Git cloné
mkdir -p $WORKDIR/rapports

cp $REPO_DIR/framework.py $WORKDIR/ 2>/dev/null
cp $REPO_DIR/mon_icon.png $WORKDIR/ 2>/dev/null
cp $REPO_DIR/common.txt $WORKDIR/ 2>/dev/null || echo -e "admin\nroot\npassword\nsecret\nmememe" > $WORKDIR/common.txt

# 4. Le Cerveau Python (VENV) - AVEC QUESTIONARY
echo -e "${GREEN}[+] 4/5 Installation des modules Python...${NC}"
cd $WORKDIR
if [ ! -d "env" ]; then
    python3 -m venv env
fi
env/bin/pip install python-nmap rich colorama requests questionary --break-system-packages 2>/dev/null || env/bin/pip install python-nmap rich colorama requests questionary

# 5. Création du lanceur blindé et du Bureau
echo -e "${GREEN}[+] 5/5 Création du lanceur auto-cicatrisant...${NC}"

# Le lanceur terminal 'cyber' ultra-robuste
echo '#!/bin/bash
echo -e "\033[0;36m[*] Vérification des mises à jour sur GitHub...\033[0m"
cd '"$REPO_DIR"' && git pull --quiet
cp framework.py '"$WORKDIR"'/
echo -e "\033[0;33m[*] Vérification des dépendances (Anti-Crash)...\033[0m"
cd '"$WORKDIR"'
./env/bin/pip install python-nmap rich colorama requests questionary --quiet --break-system-packages 2>/dev/null || ./env/bin/pip install python-nmap rich colorama requests questionary --quiet
sudo ./env/bin/python framework.py "$@"' | sudo tee /usr/local/bin/cyber > /dev/null

sudo chmod +x /usr/local/bin/cyber

# Le raccourci Bureau cliquable (.desktop)
DESKTOP_PATH=~/Desktop
echo "[Desktop Entry]
Name=Cyber Framework
Comment=Outil de Red Team automatisé
Exec=cyber
Icon=$WORKDIR/mon_icon.png
Terminal=true
Type=Application
Categories=Utility;Security;" > $DESKTOP_PATH/CyberFramework.desktop
chmod +x $DESKTOP_PATH/CyberFramework.desktop

echo -e "\n${CYAN}[*] DÉPLOIEMENT TERMINÉ !${NC}"
echo -e "-> Ton système est maintenant 100% autonome et incassable."