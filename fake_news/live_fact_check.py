from dotenv import load_dotenv
import os
import requests

load_dotenv()

API_KEY = os.getenv("NEWS_API_KEY")

def fact_check(news_text):
    keywords = news_text.split()[:5]

    query = " ".join(keywords)

    url = (
        f"https://newsapi.org/v2/everything?"
        f"q={query}"
        f"&language=en"
        f"&sortBy=relevancy"
        f"&pageSize=5"
        f"&apiKey={API_KEY}"
    )
    print("SEARCH QUERY:", query)
    response = requests.get(url)

    print("STATUS CODE:", response.status_code)

    data = response.json()
    print("SEARCH QUERY:", query)
    print("TOTAL RESULTS:", data.get("totalResults"))

    print(data)

    articles = []

    if data.get("status") == "ok":

       trusted_sources = [
    "Reuters",
    "BBC News",
    "CNN",
    "Associated Press",
    "The Guardian",
    "The Indian Express",
    "The Times of India",
    "Yahoo Entertainment",
    "Economic Times"
    ]

    for article in data.get("articles", []):

        source = article["source"]["name"]

        if source in trusted_sources:

            articles.append({
                "title": article["title"],
                "source": source
            })

            articles.append({
                "title": article["title"],
                "source": article["source"]["name"]
            })

    return articles