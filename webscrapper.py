import tkinter as tk
from tkinter import ttk, messagebox
import requests
import ssl
import socket
from bs4 import BeautifulSoup
import whois
import re

def validate_and_fix_url(url):
    """Verifica e corrige a URL para garantir que contenha o esquema http:// ou https://."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def get_ssl_info(domain):
    """Obtém informações do certificado SSL/TLS do site."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "Issuer": dict(x[0] for x in cert['issuer']),
                    "Subject": dict(x[0] for x in cert['subject']),
                    "Valid From": cert['notBefore'],
                    "Valid Until": cert['notAfter']
                }
    except Exception as e:
        return {"Error": str(e)}

def get_website_technologies(url):
    """Coleta informações sobre as tecnologias usadas no site."""
    try:
        url = validate_and_fix_url(url)
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        server = response.headers.get("Server", "Desconhecido")
        powered_by = response.headers.get("X-Powered-By", "Desconhecido")
        
        return {
            "Server": server,
            "X-Powered-By": powered_by,
            "Title": soup.title.string if soup.title else "Sem título"
        }
    except Exception as e:
        return {"Error": str(e)}

def get_whois_info(domain):
    """Obtém informações WHOIS do domínio."""
    try:
        domain_info = whois.whois(domain)
        return {
            "Registrar": domain_info.registrar,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Name Servers": domain_info.name_servers
        }
    except Exception as e:
        return {"Error": str(e)}

def scan_vulnerabilities(url):
    """Verifica vulnerabilidades comuns no site."""
    vulnerabilities = []
    try:
        url = validate_and_fix_url(url)
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        if "X-Frame-Options" not in headers:
            vulnerabilities.append("Falta X-Frame-Options (clickjacking)")
        if "Content-Security-Policy" not in headers:
            vulnerabilities.append("Falta Content-Security-Policy (injeção de código)")
        if "X-XSS-Protection" not in headers:
            vulnerabilities.append("Falta X-XSS-Protection (XSS)")
        if "Strict-Transport-Security" not in headers:
            vulnerabilities.append("Falta Strict-Transport-Security (HSTS)")
        
        if re.search(r'password', response.text, re.IGNORECASE):
            vulnerabilities.append("Possível exposição de senha na página")
    
    except Exception as e:
        vulnerabilities.append(f"Erro ao verificar vulnerabilidades: {str(e)}")
    
    return vulnerabilities if vulnerabilities else ["Nenhuma vulnerabilidade óbvia encontrada."]

def scan_website():
    """Função chamada ao pressionar o botão de escanear."""
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Aviso", "Digite um URL válido.")
        return
    
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    ssl_info = get_ssl_info(domain)
    tech_info = get_website_technologies(url)
    whois_info = get_whois_info(domain)
    vulnerabilities = scan_vulnerabilities(url)
    
    results_text.delete(1.0, tk.END)
    
    results_text.insert(tk.END, "======== SSL/TLS Info ========\n", "title")
    for key, value in ssl_info.items():
        results_text.insert(tk.END, f"{key}: {value}\n", "content")
    
    results_text.insert(tk.END, "\n======== Website Technologies ========\n", "title")
    for key, value in tech_info.items():
        results_text.insert(tk.END, f"{key}: {value}\n", "content")
    
    results_text.insert(tk.END, "\n======== WHOIS Info ========\n", "title")
    for key, value in whois_info.items():
        results_text.insert(tk.END, f"{key}: {value}\n", "content")
    
    results_text.insert(tk.END, "\n======== Vulnerabilities ========\n", "title")
    for vuln in vulnerabilities:
        results_text.insert(tk.END, f"- {vuln}\n", "content")

# Criando interface gráfica responsiva
root = tk.Tk()
root.title("Web Security Scanner")
root.geometry("700x500")

frame = ttk.Frame(root, padding=10)
frame.pack(fill="both", expand=True)

url_label = ttk.Label(frame, text="Digite o URL:")
url_label.pack()

url_entry = ttk.Entry(frame, width=70)
url_entry.pack()

scan_button = ttk.Button(frame, text="Escanear", command=scan_website)
scan_button.pack(pady=5)

results_text = tk.Text(frame, height=20, width=80, wrap=tk.WORD)
results_text.pack(expand=True, fill="both")

scrollbar = ttk.Scrollbar(frame, command=results_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
results_text.config(yscrollcommand=scrollbar.set)

# Adicionando tags de estilo
results_text.tag_configure("title", font=("Helvetica", 12, "bold"), spacing1=10, spacing3=10)
results_text.tag_configure("content", font=("Helvetica", 10), spacing1=2, spacing3=2)

root.mainloop()
