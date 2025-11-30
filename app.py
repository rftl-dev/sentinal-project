from flask import Flask, request, jsonify
from flask_cors import CORS
from textblob import TextBlob

app = Flask(__name__)
# Enable CORS to allow your InfinityFree site to talk to this Render server
CORS(app) 

# --- THE PSYCHOLOGY ENGINE ---
# We detect INTENT, not just keywords.
SCAM_PSYCHOLOGY = {
    "Artificial Urgency": [
        "immediately", "urgent", "24 hours", "suspended", "locked", 
        "police", "arrest", "expires", "deadline", "act now"
    ],
    "Financial Coercion": [
        "gift card", "crypto", "bitcoin", "wire transfer", "cash app", 
        "deposit", "fee", "payment", "bank transfer", "western union"
    ],
    "Too Good To Be True": [
        "lottery", "winner", "inheritance", "million", "compensation", 
        "fund", "congratulations", "selected", "prize"
    ],
    "Authority Bias": [
        "irs", "fbi", "customs", "law enforcement", "microsoft support", 
        "bank security", "manager", "ceo", "government"
    ]
}

@app.route('/')
def home():
    return "Sentinal Brain is Active 🟢"

@app.route('/analyze', methods=['POST'])
def analyze_intent():
    data = request.json
    # Handle empty input
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data.get('text', '').lower()
    
    score = 0
    detected_tactics = []
    
    # 1. Psychological Trigger Analysis
    for tactic, keywords in SCAM_PSYCHOLOGY.items():
        found_words = [word for word in keywords if word in text]
        if found_words:
            # We add points for the category (once), not per word
            score += 25
            detected_tactics.append({
                "tactic": tactic,
                "description": f"Uses words like '{found_words[0]}' to bypass critical thinking.",
                "icon": "bi-exclamation-triangle-fill"
            })

    # 2. Sentiment Analysis (The "Kindly" Trap)
    # Scammers use hyper-polite language ("Kindly do the needful") to build false trust.
    blob = TextBlob(text)
    # If text contains "kindly" AND is very positive/polite
    if "kindly" in text and blob.sentiment.polarity > 0.1:
        score += 15
        detected_tactics.append({
            "tactic": "Calculated Politeness",
            "description": "Uses overly polite language ('kindly') to lower your defenses.",
            "icon": "bi-chat-heart-fill"
        })

    # 3. Cap score at 100
    final_score = min(score, 100)

    # 4. Generate The Verdict
    verdict = "Safe"
    if final_score > 30: verdict = "Suspicious"
    if final_score > 70: verdict = "Malicious"

    return jsonify({
        "score": final_score,
        "verdict": verdict,
        "tactics": detected_tactics
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)