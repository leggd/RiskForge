import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("XAI_API_KEY")

if key:
    print("✅ Успех! Ключ найден и загружен.")
    # Печатаем первые 4 символа для проверки (безопасно)
    print(f"Начало ключа: {key[:4]}...")
else:
    print("❌ Ошибка: Ключ не найден. Проверь файл .env")