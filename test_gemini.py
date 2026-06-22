import google.generativeai as genai

import os
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-2.5-flash")

response = model.generate_content(
    "Say Hello, Gemini is working."
)

print(response.text)