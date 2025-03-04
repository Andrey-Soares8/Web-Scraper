# Web Security Scanner

## Descrição
Este é um scanner de segurança para sites desenvolvido com Python e a biblioteca Tkinter para interface gráfica. O programa permite analisar informações de SSL/TLS, tecnologias utilizadas pelo site, dados WHOIS do domínio e possíveis vulnerabilidades de segurança.

## Funcionalidades
- **Verificação SSL/TLS**: Obtém informações do certificado do site.
- **Detecção de tecnologias**: Identifica o servidor e tecnologias usadas no site.
- **Consulta WHOIS**: Obtém dados sobre o domínio, como provedor de registro e datas de criação/expiração.
- **Escaneamento de vulnerabilidades**: Analisa o site para verificar cabeçalhos de segurança e possíveis exposições de informações sensíveis.

## Tecnologias Utilizadas
- **Python**
- **Tkinter** (Interface Gráfica)
- **Requests** (Requisições HTTP)
- **BeautifulSoup** (Análise de HTML)
- **Whois** (Consulta de domínios)
- **SSL e Socket** (Verificação de certificado SSL/TLS)
- **Regex** (Verificação de vulnerabilidades básicas)

## Instalação
Antes de executar o código, instale as dependências necessárias:
```bash
pip install requests beautifulsoup4 python-whois
```

## Como Usar
1. Execute o script Python:
   ```bash
   python scanner.py
   ```
2. Digite a URL do site que deseja escanear.
3. Clique no botão "Escanear" e aguarde os resultados.

## Observações
- O programa pode não funcionar corretamente em sites que possuem bloqueios contra web scraping.
- Algumas informações WHOIS podem estar ocultas dependendo da configuração do domínio.
- Os testes de vulnerabilidades são básicos e não substituem uma auditoria profissional.

## Licença
Este projeto está licenciado sob a MIT License.

