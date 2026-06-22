import pandas as pd

fake = pd.read_csv("Fake.csv")
true = pd.read_csv("True.csv")

fake["label"] = 0
true["label"] = 1

df = pd.concat([fake, true])
fake["content"] = fake["title"] + " " + fake["text"]
true["content"] = true["title"] + " " + true["text"]

df = pd.concat([fake, true])

df = df[["content", "label"]]

df.rename(columns={"content": "text"}, inplace=True)

df.to_csv("news.csv", index=False)

print("Dataset Created")