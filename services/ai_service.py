import requests
import urllib3
import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL   = "llama-3.1-8b-instant"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sends a single prompt to Groq API and returns the text response
def groq_post(system_msg, user_msg, temperature=0.15):
    """
    Send a prompt to the Groq API and obtain the response text
    """
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json={
                "model": GROQ_MODEL,
                "max_tokens": 1024,
                "temperature": temperature,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user",   "content": user_msg},
                ],
            },
            timeout=90,
            verify=False,
        )
        data = r.json()
        if "choices" not in data:
            print("AI", f"Bad response: {str(data)[:200]}")
            return None
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        print("AI", f"Request failed: {e}")
        return None

def generate_ai(description):
    """
    Generate an AI vulnerability analysis from a ticket description
    """
    if not description:
        return "No vulnerability data available for AI analysis."

    prompt = f"""
    You are a senior cybersecurity analyst.

    Analyse the following vulnerability report and provide clear, practical guidance.

    --- REPORT ---
    {description}
    ---

    Respond with:

    ### Explanation
    Explain what the vulnerability is in simple terms.

    ### Risk
    Explain what an attacker could realistically do.

    ### Remediation Steps
    Provide clear, step-by-step instructions to fix the issue.

    Keep it concise and actionable. Avoid generic advice.
    """

    return groq_post(
        system_msg="You are a senior cybersecurity analyst.",
        user_msg=prompt,
        temperature=0.2)