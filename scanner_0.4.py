import nmap
import subprocess
import os
import requests
from dotenv import load_dotenv

# Load environment variables / Загружаем переменные окружения
load_dotenv()

# Dictionary with all interface strings / Словарь со всеми строками интерфейса
LOCALIZATION = {
    "1": {  # English
        "lang_name": "en",
        "start": "=== SECURITY ORCHESTRATOR v0.4 ===",
        "input_ip": "Enter target IP: ",
        "nmap_run": "[1/4] Running Deep Nmap scan (vulns & scripts)...",
        "web_run": "[2/4] Web detected! Running Nikto, Nuclei & SSLScan...",
        "ai_run": "[4/4] AI Analysis (Llama 3.1)...",
        "report_header": " FINAL SECURITY REPORT ",
        "sys_prompt": "You are a Senior Penethrator/Red Team expert. Analyze logs from Nmap (vulns), Nikto, Nuclei, and SSLScan. Highlight critical threats and provide a step-by-step fix guide in ENGLISH."
    },
    "2": {  # Русский
        "lang_name": "ru",
        "start": "=== ОРКЕСТРАТОР БЕЗОПАСНОСТИ v0.4 ===",
        "input_ip": "Введите IP цели: ",
        "nmap_run": "[1/4] Глубокое сканирование Nmap (уязвимости и скрипты)...",
        "web_run": "[2/4] Найдена веб-цель! Запуск Nikto, Nuclei и SSLScan...",
        "ai_run": "[4/4] Анализ ИИ (Llama 3.1)...",
        "report_header": " ИТОГОВЫЙ ОТЧЕТ БЕЗОПАСНОСТИ ",
        "sys_prompt": "Ты ведущий эксперт по кибербезопасности. Проанализируй логи Nmap (vulns), Nikto, Nuclei и SSLScan. Выдели критические угрозы и напиши пошаговый план исправления на РУССКОМ языке."
    }
}

def run_nmap(target, t):
    """Phase 1: Deep Nmap with scripts / Фаза 1: Глубокий Nmap со скриптами"""
    print(t["nmap_run"])
    nm = nmap.PortScanner()
    # Adding -sC for default scripts / Добавляем -sC для стандартных скриптов
    nm.scan(target, arguments='-sV -sC --script vuln -T4')
    
    results = ""
    is_web = False
    
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                svc = nm[target][proto][port]
                results += f"\n[PORT {port}] {svc['name']} ({svc['version']})\n"
                
                # IMPORTANT: Extracting script results (CVEs, etc.) 
                # ВАЖНО: Извлекаем результаты скриптов (CVE и др.)
                if 'script' in svc:
                    for script_id, script_out in svc['script'].items():
                        results += f"  > Script {script_id}: {script_out[:500]}...\n"
                
                if port in [80, 443, 8080] or svc['name'] in ['http', 'https']:
                    is_web = True
    return results, is_web

def run_sslscan(target):
    """New: SSL/TLS analysis / Новое: Анализ SSL/TLS"""
    # --no-colour is vital for clean logs / --no-colour критичен для чистых логов
    res = subprocess.run(['sslscan', '--no-colour', target], capture_output=True, text=True)
    return res.stdout

def run_web_scanners(target, t):
    """Phase 2: Full Web Suite / Фаза 2: Полный веб-пакет"""
    print(t["web_run"])
    
    # 1. Nikto
    nikto = subprocess.run(['nikto', '-h', target, '-maxtime', '120s', '-nointeractive'], 
                            capture_output=True, text=True)
    
    # 2. Nuclei (Now with Medium severity / Теперь со средними уязвимостями)
    nuclei = subprocess.run(['nuclei', '-u', target, '-severity', 'medium,high,critical', '-silent'], 
                             capture_output=True, text=True)
    
    # 3. SSLScan
    ssl_data = run_sslscan(target)
    
    return f"--- NIKTO ---\n{nikto.stdout}\n--- NUCLEI ---\n{nuclei.stdout}\n--- SSLSCAN ---\n{ssl_data}"

def get_ai_analysis(full_data, t):
    """Phase 3: Deep AI Verdict / Фаза 3: Глубокий вердикт ИИ"""
    print(t["ai_run"])
    api_key = os.getenv("GROQ_API_KEY")
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": t["sys_prompt"]},
            {"role": "user", "content": f"Logs for analysis:\n{full_data}"}
        ],
        "temperature": 0.2
    }
    
    try:
        response = requests.post(url, headers={"Authorization": f"Bearer {api_key}"}, json=payload)
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"AI Error / Ошибка ИИ: {e}"

if __name__ == "__main__":
    print("Select Language / Выберите язык (1: EN, 2: RU):")
    choice = input(">> ")
    t = LOCALIZATION.get(choice, LOCALIZATION["1"])
    
    print(f"\n{t['start']}")
    target_ip = input(t["input_ip"])
    
    # 1. Nmap
    nmap_data, web_found = run_nmap(target_ip, t)
    total_report = f"--- NMAP DATA (DETAILED) ---\n{nmap_data}\n"
    
    # 2. Web (if needed)
    if web_found:
        total_report += run_web_scanners(target_ip, t)
    
    # 3. AI
    verdict = get_ai_analysis(total_report, t)
    
    # Output / Вывод
    print("\n" + "="*80)
    print(f" {t['report_header']} ")
    print("="*80)
    print(verdict)
    print("="*80)