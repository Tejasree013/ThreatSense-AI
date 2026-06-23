import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

model = genai.GenerativeModel("gemini-2.5-flash")

def ask_ai(question, report_data=None):

    if report_data:
        prompt = f"""
You are ThreatSense AI, an expert Cybersecurity Assistant.

Security Report:
{report_data}

User Question:
{question}

Use both the report and your cybersecurity knowledge to answer.
"""
    else:
        prompt = f"""
You are ThreatSense AI, an expert Cybersecurity Assistant.

Answer the following cybersecurity question professionally:

{question}
"""

    response = model.generate_content(prompt)

    return response.text