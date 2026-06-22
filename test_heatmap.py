from utils.threat_heatmap import (
    calculate_threat_levels,
    get_overall_threat_level,
    generate_heatmap
)

scores = calculate_threat_levels(
    harmful_words_count=8,
    suspicious_links_count=2,
    suspicious_images_count=1,
    executable_count=1
)

overall = get_overall_threat_level(scores)

print("\nTHREAT HEATMAP")
print("-" * 40)
print(generate_heatmap(scores))

print("\nOverall Threat Level:")
print(overall["threat_level"])

print("Average Score:")
print(overall["average_score"])