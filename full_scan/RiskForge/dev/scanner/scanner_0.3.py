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
        "start": "=== SECURITY ORCHESTRATOR v1.1 ===",
        "input_ip": "Enter target IP: ",
        "nmap_run": "[1/3] Running Nmap reconnaissance...",
        "web_run": "[2/3] Web detected! Running Nikto & Nuclei...",
        "ai_run": "[3/3] AI Analysis (Llama 3.1)...",
        "report_header": " FINAL SECURITY REPORT ",
        "sys_prompt": "You are a Red Team expert. Analyze logs from Nmap, Nikto, and Nuclei. Highlight critical vulnerabilities and provide remediation steps in ENGLISH."
    },
    "2": {  # Русский
        "lang_name": "ru",
        "start": "=== ОРКЕСТРАТОР БЕЗОПАСНОСТИ v1.1 ===",
        "input_ip": "Введите IP цели: ",
        "nmap_run": "[1/3] Запуск разведки Nmap...",
        "web_run": "[2/3] Обнаружен веб-сервис! Запуск Nikto и Nuclei...",
        "ai_run": "[3/3] Анализ ИИ (Llama 3.1)...",
        "report_header": " ИТОГОВЫЙ ОТЧЕТ БЕЗОПАСНОСТИ ",
        "sys_prompt": "Ты эксперт Red Team. Проанализируй логи Nmap, Nikto и Nuclei. Выдели критические уязвимости и напиши план исправления на РУССКОМ языке."
    }
}

def run_nmap(target, t):
    """Phase 1: Nmap / Фаза 1: Nmap"""
    print(t["nmap_run"])
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --script vuln -T4')
    
    results = ""
    is_web = False
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                svc = nm[target][proto][port]
                results += f"Port: {port} | Service: {svc['name']} | Ver: {svc['version']}\n"
                if port in [80, 443, 8080] or svc['name'] in ['http', 'https']:
                    is_web = True
    return results, is_web

def run_web_scanners(target, t):
    """Phase 2: Nikto & Nuclei / Фаза 2: Nikto и Nuclei"""
    print(t["web_run"])
    # Run Nikto / Запуск Nikto
    nikto = subprocess.run(['nikto', '-h', target, '-maxtime', '120s', '-nointeractive'], 
                            capture_output=True, text=True)
    # Run Nuclei / Запуск Nuclei
    nuclei = subprocess.run(['nuclei', '-u', target, '-severity', 'info,low,medium,high,critical', '-silent'], 
                             capture_output=True, text=True)
    return f"--- NIKTO ---\n{nikto.stdout}\n--- NUCLEI ---\n{nuclei.stdout}"

def get_ai_analysis(full_data, t):
    """Phase 3: AI Analysis / Фаза 3: Анализ ИИ"""
    print(t["ai_run"])
    api_key = os.getenv("GROQ_API_KEY")
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": t["sys_prompt"]},
            {"role": "user", "content": f"Analyze logs:\n{full_data}"}
        ],
        "temperature": 0.2
    }
    
    try:
        response = requests.post(url, headers={"Authorization": f"Bearer {api_key}"}, json=payload)
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"Error / Ошибка: {e}"

if __name__ == "__main__":
    # Language Selection / Выбор языка
    print("Select Language / Выберите язык:")
    print("1: English")
    print("2: Русский")
    choice = input(">> ")
    
    # Default to English if invalid choice / По умолчанию английский, если ввод неверный
    t = LOCALIZATION.get(choice, LOCALIZATION["1"])
    
    print(f"\n{t['start']}")
    target_ip = input(t["input_ip"])
    
    # Logic / Логика
    nmap_logs, web_found = run_nmap(target_ip, t)
    report = f"--- NMAP ---\n{nmap_logs}\n"
    
    if web_found:
        report += run_web_scanners(target_ip, t)
    
    verdict = get_ai_analysis(report, t)
    
    # Final Output / Финальный вывод
    print("\n" + "="*70)
    print(f" {t['report_header']} ")
    print("="*70)
    print(verdict)
    print("="*70)