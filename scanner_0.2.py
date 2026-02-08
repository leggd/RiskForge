import nmap
import os
import requests
import subprocess
from dotenv import load_dotenv

# Load environment variables / Загружаем переменные окружения
load_dotenv()

# Localization / Локализация интерфейса
TRANSLATIONS = {
    "ru": {
        "header": "=== КОРПОРАТИВНЫЙ ОРКЕСТРАТОР БЕЗОПАСНОСТИ ===",
        "start_nmap": "[1/3] Запуск разведки Nmap (порты и CVE)...",
        "start_nikto": "[2/3] Обнаружен HTTP/HTTPS. Запуск глубокого сканирования Nikto...",
        "ai_analysis": "[3/3] Глубокий анализ данных через Llama 3.1 (Groq)...",
        "input_ip": "Введите IP-адрес цели: ",
        "raw_data_header": "\n--- СВОДНЫЙ ОТЧЕТ ВСЕХ СКАНЕРОВ ---",
        "verdict_title": "ВЕРДИКТ ИИ (ЭКСПЕРТНЫЙ АНАЛИЗ):",
        "system_role": "Ты ведущий ИБ-аналитик (Red Team). Проанализируй логи Nmap и Nikto. Выдели критические уязвимости (особенно EXPLOIT) и напиши план исправления на РУССКОМ языке."
    },
    "en": {
        "header": "=== CORPORATE SECURITY ORCHESTRATOR ===",
        "start_nmap": "[1/3] Running Nmap reconnaissance (ports & CVEs)...",
        "start_nikto": "[2/3] Web service detected. Running deep Nikto scan...",
        "ai_analysis": "[3/3] Deep data analysis via Llama 3.1 (Groq)...",
        "input_ip": "Enter target IP address: ",
        "raw_data_header": "\n--- AGGREGATED SCANNER REPORT ---",
        "verdict_title": "AI VERDICT (EXPERT ANALYSIS):",
        "system_role": "You are a lead security analyst (Red Team). Analyze Nmap and Nikto logs. Highlight critical vulnerabilities (especially EXPLOITS) and write a remediation plan in ENGLISH."
    }
}

def run_nmap(target_ip, lang):
    """
    Standard reconnaissance scan using Nmap.
    Стандартная разведка через Nmap.
    """
    t = TRANSLATIONS[lang]
    print(t["start_nmap"])
    nm = nmap.PortScanner()
    
    # -sV: version detection, --script vuln: check for CVEs
    nm.scan(target_ip, arguments='-sV --script vuln -T4')
    
    scan_results = []
    web_detected = False
    
    if target_ip in nm.all_hosts():
        host_info = nm[target_ip]
        scan_results.append(f"HOST: {target_ip} ({host_info.state()})")
        
        for proto in host_info.all_protocols():
            for port in host_info[proto].keys():
                service = host_info[proto][port]
                scan_results.append(f"Port: {port} | Service: {service['name']} | Ver: {service['version']}")
                
                # Check if we should trigger Nikto (ports 80, 443, 8080)
                if port in [80, 443, 8080] or service['name'] in ['http', 'https']:
                    web_detected = True
                
                if 'script' in service:
                    for s_id, out in service['script'].items():
                        scan_results.append(f"  [!] {s_id.upper()}: {out}")
    
    return "\n".join(scan_results), web_detected

def run_nikto(target_ip, lang):
    """
    Web vulnerability scan with a 5-minute internal limit.
    Веб-сканирование с внутренним лимитом в 5 минут.
    """
    t = TRANSLATIONS[lang]
    print(t["start_nikto"])
    
    nikto_path = "/home/ladimyr/Desktop/nikto/program/nikto.pl"
    
    try:
        # Добавляем '-maxtime 300s' (максимум 5 минут на скан)
        # Убираем жесткий timeout из subprocess или ставим его больше
        result = subprocess.run(
            ['perl', nikto_path, '-h', target_ip, '-Tuning', '123b', '-nointeractive', '-maxtime', '300s'], 
            capture_output=True, 
            text=True, 
            timeout=400 
        )
        return result.stdout if result.stdout else "Nikto finished with no output."
    except subprocess.TimeoutExpired:
        return "Nikto timed out, but we proceed with Nmap data."
    except Exception as e:
        return f"Nikto Execution Error / Ошибка Nikto: {e}"

def get_ai_analysis(combined_report, lang):
    """
    Sends aggregated data to Llama 3.1 for a final security verdict.
    Отправляет сводные данные в Llama 3.1 для финального вердикта.
    """
    t = TRANSLATIONS[lang]
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "Error: GROQ_API_KEY not found in .env"

    print(t["ai_analysis"])
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": t["system_role"]},
            {"role": "user", "content": combined_report}
        ],
        "temperature": 0.3 # Precision over creativity / Точность важнее креативности
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"AI API Error / Ошибка ИИ: {e}"

if __name__ == "__main__":
    # Language selection / Выбор языка
    print("Select Language / Выберите язык:")
    print("1: English")
    print("2: Русский")
    lang_code = input(">> ")
    lang = "en" if lang_code == "1" else "ru"
    t = TRANSLATIONS[lang]
    
    print(f"\n{t['header']}")
    target_ip = input(t["input_ip"])
    
    # PHASE 1: Nmap Reconnaissance
    nmap_data, web_found = run_nmap(target_ip, lang)
    
    # PHASE 2: Aggregation & Optional Nikto Scan
    full_report = f"--- SCAN REPORT FOR {target_ip} ---\n"
    full_report += f"\n[NMAP RECON DATA]\n{nmap_data}\n"
    
    if web_found:
        nikto_data = run_nikto(target_ip, lang)
        full_report += f"\n[NIKTO WEB VULNERABILITY DATA]\n{nikto_data}\n"
    
    # Show Raw Data for the team / Показать сырые данные команде
    print(t["raw_data_header"])
    print("-" * 30)
    print(full_report)
    print("-" * 30)
    
    # PHASE 3: AI Verdict
    verdict = get_ai_analysis(full_report, lang)
    
    print("\n" + "="*60)
    print(f" {t['verdict_title']} ")
    print("="*60)
    print(verdict)
    print("="*60)