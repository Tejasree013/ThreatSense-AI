from fake_news_detector import detect_news

news = input("Enter News:\n")

result, confidence, risk = detect_news(news)

print("\nNEWS ANALYSIS REPORT")
print("=" * 40)

print("Prediction :", result)
print("Confidence :", confidence, "%")
print("Risk Level :", risk)