import nmap
import os
import requests
from dotenv import load_dotenv

# Load environment variables / Загружаем переменные окружения
load_dotenv()

# Localization dictionary / Словарь локализации
TRANSLATIONS = {
    "ru": {
        "start_scan": "\n[1/2] Сканирование {target} запущено...",
        "ai_analysis": "[2/2] Анализ данных через Llama 3.1 (Groq)...",
        "error_target": "Ошибка: Цель недоступна или блокирует сканирование.",
        "error_key": "Ошибка: API ключ Groq не найден в .env",
        "raw_data": "--- СЫРЫЕ ДАННЫЕ СКАНЕРА ---",
        "verdict_title": "ВЕРДИКТ ИИ:",
        "input_ip": "Введите IP-адрес второй машины: ",
        "system_role": "Ты профессиональный ИБ-аналитик. Отвечай НА РУССКОМ ЯЗЫКЕ. Проанализируй отчет Nmap, выдели критические уязвимости и дай рекомендации.",
        "header": "=== КОРПОРАТИВНЫЙ СКАНЕР УЯЗВИМОСТЕЙ (PROTOTYPE) ==="
    },
    "en": {
        "start_scan": "\n[1/2] Scanning {target} started...",
        "ai_analysis": "[2/2] Analyzing data via Llama 3.1 (Groq)...",
        "error_target": "Error: Target is down or blocking the scan.",
        "error_key": "Error: Groq API key not found in .env",
        "raw_data": "--- RAW SCANNER DATA ---",
        "verdict_title": "AI VERDICT:",
        "input_ip": "Enter the IP address of the target machine: ",
        "system_role": "You are a professional security analyst. Answer in ENGLISH. Analyze the Nmap report, highlight critical vulnerabilities, and provide remediation steps.",
        "header": "=== CORPORATE VULNERABILITY SCANNER (PROTOTYPE) ==="
    }
}

def scan_vulnerabilities(target_ip, lang):
    """
    Scans ports, services and looks for vulnerabilities using Nmap scripts.
    Сканирует порты, сервисы и ищет уязвимости через скрипты Nmap.
    """
    t = TRANSLATIONS[lang]
    nm = nmap.PortScanner()
    
    print(t["start_scan"].format(target=target_ip))
    # -sV: service version detection / определение версий программ
    # --script vuln: audit for known vulnerabilities / аудит известных уязвимостей
    nm.scan(target_ip, arguments='-sV --script vuln -T4')
    
    if target_ip not in nm.all_hosts():
        return t["error_target"]

    report_data = []
    host_info = nm[target_ip]
    
    report_data.append(f"HOST: {target_ip} ({host_info.hostname()})")
    report_data.append(f"STATE: {host_info.state()}")

    for proto in host_info.all_protocols():
        for port in host_info[proto].keys():
            service = host_info[proto][port]
            port_str = f"\nPORT: {port}/{proto} | SERVICE: {service['name']} | VERSION: {service['version']}"
            report_data.append(port_str)
            
            if 'script' in service:
                for script_name, output in service['script'].items():
                    report_data.append(f"  ⚠️ [!] {script_name.upper()}: {output}")
    
    return "\n".join(report_data)

def ask_ai_for_analysis(scan_text, lang):
    """
    Sends raw scan data to Llama 3.1 for expert assessment.
    Отправляет сырые данные сканирования в Llama 3.1 для экспертной оценки.
    """
    t = TRANSLATIONS[lang]
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    
    if not GROQ_API_KEY:
        return t["error_key"]

    print(t["ai_analysis"])
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": t["system_role"]},
            {"role": "user", "content": scan_text}
        ],
        "temperature": 0.2
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"Error/Ошибка: {e}"

if __name__ == "__main__":
    # Language selection / Выбор языка
    print("Select language / Выберите язык:")
    print("1: English")
    print("2: Русский")
    lang_choice = input("Choice / Выбор (1/2): ")
    lang = "en" if lang_choice == "1" else "ru"
    
    t = TRANSLATIONS[lang]
    print(f"\n{t['header']}")
    
    target = input(t["input_ip"])
    
    # 1. Nmap Scan / Запуск Nmap
    raw_results = scan_vulnerabilities(target, lang)
    print(f"\n{t['raw_data']}")
    print(raw_results)
    
    # 2. AI Analysis / Анализ ИИ
    if "Ошибка" not in raw_results and "Error" not in raw_results:
        final_verdict = ask_ai_for_analysis(raw_results, lang)
        print("\n" + "="*50)
        print(t["verdict_title"])
        print("="*50)
        print(final_verdict)
    else:
        print(raw_results)