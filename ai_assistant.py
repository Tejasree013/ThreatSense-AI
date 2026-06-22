import google.generativeai as genai
import os

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

model = genai.GenerativeModel("gemini-2.5-flash")

def ask_ai(question, report_data):

    prompt = f"""
You are an AI Cybersecurity Assistant.

Analyze the following security report and answer only based on the report.

Security Report:

{report_data}

User Question:
{question}

Provide a short and professional answer.
"""

    response = model.generate_content(prompt)

    return response.text