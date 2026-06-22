from flask import Flask, request, render_template, redirect
from threat_detector import *
from security_analysis import generate_security_explanation
from ai_assistant import ask_ai
import os
from pymongo import MongoClient
import bcrypt
from fake_news.fake_news_detector import detect_news
from fake_news.live_fact_check import fact_check
from utils.threat_heatmap import (
    calculate_threat_levels,
    get_overall_threat_level,
    generate_heatmap
)

app = Flask(__name__)
app.secret_key = "madhu_secret_key"

latest_report = {}

from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["document_security"]
users = db["users"]

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return redirect("/login")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = users.find_one({"email": email})

        if existing_user:
            return "Email already exists"

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password
        })

        return redirect("/login")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = users.find_one({"email": email})

        if user and bcrypt.checkpw(
            password.encode("utf-8"),
            user["password"]
        ):
            app.config["CURRENT_USER_NAME"] = user["name"]
            app.config["CURRENT_USER_EMAIL"] = user["email"]

            return render_template(
                "index.html",
                page="dashboard",
                user_name=user["name"],
                user_email=user["email"]
            )

        return "Invalid Email or Password"

    return render_template("login.html")


@app.route("/scan", methods=["POST"])
def scan():
    global latest_report

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return "No file selected"

    path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
    uploaded_file.save(path)

    text = extract_text(path)

    harmful = detect_harmful_words(text)
    urls = extract_urls(text)
    bad_links = suspicious_links(urls)
    executables = detect_executables(text)

    images = count_images(path)
    image_threats = scan_images_for_harmful_text(path)

    all_image_keywords = []

    for img in image_threats:
        all_image_keywords.extend(img["keywords"])

    all_harmful = harmful + all_image_keywords

    score = calculate_risk(
        all_harmful,
        bad_links,
        images
    )

    result = classify(score)

    heatmap_scores = calculate_threat_levels(
        harmful_words_count=len(all_harmful),
        suspicious_links_count=len(bad_links),
        suspicious_images_count=len(image_threats),
        executable_count=len(executables)
    )

    overall_threat = get_overall_threat_level(heatmap_scores)
    heatmap = generate_heatmap(heatmap_scores)

    analysis = generate_security_explanation(
        all_harmful,
        bad_links,
        executables,
        score
    )

    latest_report = {
        "risk_score": score,
        "risk_level": analysis["risk_level"],
        "keywords": all_harmful,
        "links": bad_links,
        "executables": executables,
        "keyword_count": len(all_harmful),
        "link_count": len(bad_links),
        "image_count": images,
        "suspicious_image_count": len(image_threats),
        "exe_count": len(executables),
        "heatmap_scores": heatmap_scores,
        "overall_threat": overall_threat,
        "image_threats": image_threats,
        "threat_message": analysis["threat"]
    }

    report = ""
    report += "DOCUMENT SECURITY REPORT\n"
    report += "=" * 40 + "\n\n"
    report += f"Status      : {result}\n"
    report += f"Risk Score  : {score}\n\n"

    report += "AI SECURITY ANALYSIS\n"
    report += "=" * 40 + "\n\n"
    report += f"Risk Level : {analysis['risk_level']}\n"
    report += f"Risk Score : {analysis['risk_score']}\n"
    report += f"AI Confidence : {analysis['confidence']}%\n\n"

    report += "This document contains:\n"
    report += f"• {analysis['keyword_count']} malware-related keywords\n"
    report += f"• {analysis['link_count']} suspicious URL(s)\n"
    report += f"• {analysis['exe_count']} executable file reference(s)\n\n"

    report += "Potential Threat:\n"
    report += f"{analysis['threat']}\n\n"


    report += "SUSPICIOUS WORDS\n"

    if harmful:
        for word in harmful:
            report += f"✓ {word}\n"
    else:
        report += "No suspicious words found\n"

    report += "\nSUSPICIOUS LINKS\n"

    if bad_links:
        for link in bad_links:
            report += f"✓ {link}\n"
    else:
        report += "No suspicious links found\n"

    report += "\nEXECUTABLE FILES\n"

    if executables:
        for exe in executables:
            report += f"✓ {exe}\n"
    else:
        report += "No executable files found\n"

    report += "\nIMAGE ANALYSIS\n\n"

    if images > 0:
        report += f"Total Images : {images}\n\n"

        for img in image_threats:
            report += f"IMAGE {img['image_no']}\n"
            report += "-" * 25 + "\n"

            if img["keywords"]:
                report += "Status : SUSPICIOUS\n\n"
                report += "Detected Keywords:\n"

                for word in img["keywords"]:
                    report += f"✓ {word}\n"
            else:
                report += "Status : SAFE\n"
                report += "No harmful content detected\n"

            if img["ocr_text"]:
                report += "\nOCR Extracted Text:\n"
                report += img["ocr_text"][:500]
                report += "\n"

            report += "\n"
    else:
        report += "No images found\n"
        report += "Status : SAFE\n"

    return render_template(
        "index.html",
        page="document",
        report=report,
        score=score,
        risk=result,
        analysis=analysis,
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )


@app.route("/check_news", methods=["POST"])
def check_news():
    news = request.form["news"]

    result, confidence, risk = detect_news(news)
    articles = fact_check(news)

    if articles:
        final_verdict = "LIKELY REAL NEWS"
    else:
        final_verdict = result

    report = "\n"
    report += "NEWS ANALYSIS REPORT\n"
    report += "=" * 40 + "\n\n"
    report += f"Prediction : {result}\n"
    report += f"Confidence : {confidence} %\n"
    report += f"Risk Level : {risk}\n"
    report += f"Final Verdict : {final_verdict}\n\n"

    report += "LIVE FACT CHECK\n"
    report += "=" * 40 + "\n\n"

    if articles:
        report += "Matching Articles Found:\n\n"

        for article in articles:
            report += f"✓ {article['source']}\n"
            report += f"  {article['title']}\n\n"
    else:
        report += "No matching articles found\n"

    return render_template(
        "index.html",
        page="news",
        report=report,
        prediction=result,
        confidence=confidence,
        risk=risk,
        verdict=final_verdict,
        articles=articles,
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )


@app.route("/ask_ai", methods=["POST"])
def ask_ai_route():

    question = request.form["question"]

    answer = ask_ai(
        question,
        latest_report
    )

    return render_template(
        "index.html",
        page="assistant",
        question=question,
        answer=answer,
        user_name=app.config.get(
            "CURRENT_USER_NAME",
            "User"
        ),
        user_email=app.config.get(
            "CURRENT_USER_EMAIL",
            "user@email.com"
        )
    )
@app.route("/logout")
def logout():

    app.config["CURRENT_USER_NAME"] = ""
    app.config["CURRENT_USER_EMAIL"] = ""

    return redirect("/login")

@app.route("/dashboard")
def dashboard():
    return render_template(
        "index.html",
        page="dashboard",
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )


@app.route("/document-scanner")
def document_scanner():
    return render_template(
        "index.html",
        page="document",
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )


@app.route("/fake-news")
def fake_news():
    return render_template(
        "index.html",
        page="news",
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )


@app.route("/heatmap")
def heatmap():

    latest_report_data = {
        "keyword_count": latest_report.get("keyword_count", 0),
        "link_count": latest_report.get("link_count", 0),
        "image_count": latest_report.get("image_count", 0),
        "exe_count": latest_report.get("exe_count", 0)
    }

    return render_template(
        "index.html",
        page="heatmap",
        latest_report=latest_report_data,
        heatmap_scores=latest_report.get("heatmap_scores", {}),
        overall_threat=latest_report.get("overall_threat", {}),
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )
@app.route("/assistant")
def assistant():
    return render_template(
        "index.html",
        page="assistant",
        user_name=app.config.get("CURRENT_USER_NAME", "User"),
        user_email=app.config.get("CURRENT_USER_EMAIL", "user@email.com")
    )



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)