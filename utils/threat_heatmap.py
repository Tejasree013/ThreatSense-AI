def calculate_threat_levels(
    harmful_words_count,
    suspicious_links_count,
    suspicious_images_count,
    executable_count
):
    
    # Keywords Score
    if harmful_words_count == 0:
        keywords_score = 0
    elif harmful_words_count <= 2:
        keywords_score = 20
    elif harmful_words_count <= 5:
        keywords_score = 50
    elif harmful_words_count <= 10:
        keywords_score = 80
    else:
        keywords_score = 100

    # Links Score
    if suspicious_links_count == 0:
        links_score = 0
    elif suspicious_links_count == 1:
        links_score = 30
    elif suspicious_links_count == 2:
        links_score = 60
    else:
        links_score = 100

    # Images Score
    if suspicious_images_count == 0:
        images_score = 0
    elif suspicious_images_count == 1:
        images_score = 40
    elif suspicious_images_count == 2:
        images_score = 70
    else:
        images_score = 100

    # Executable Score
    executable_score = 100 if executable_count > 0 else 0

    return {
        "keywords": keywords_score,
        "links": links_score,
        "images": images_score,
        "executables": executable_score
    }
def get_overall_threat_level(scores):

    average_score = sum(scores.values()) / len(scores)

    if average_score <= 30:
        level = "LOW"
    elif average_score <= 70:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "average_score": round(average_score, 2),
        "threat_level": level
    }
def generate_heatmap(scores):

    heatmap = []

    for category, score in scores.items():
        blocks = "#" * (score // 10)
        heatmap.append(
            f"{category.capitalize():12} {blocks:<10} {score}%"
        )

    return "\n".join(heatmap)