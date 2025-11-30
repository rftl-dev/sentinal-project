from flask import Flask, request, jsonify
from flask_cors import CORS
from textblob import TextBlob
import re

app = Flask(__name__)
CORS(app) 

# --- THE ADVANCED THREAT DATABASE ---
# Weighted keywords: Higher number = Higher risk
THREAT_INDICATORS = {
    # 1. The "Fear" Tactics (Tech Support / IRS / Police)
    "high_fear": {
        "keywords": ["virus", "infected", "hacked", "breach", "compromised", "suspended", "locked", "banned", "deactivated", "warrant", "arrest", "legal action", "police", "fbi", "irs", "lawsuit", "trojan", "malware", "spyware"],
        "score": 30,
        "label": "Fear Mongering"
    },
    # 2. The "Greed" Tactics (Lottery / Inheritance / Crypto)
    "high_greed": {
        "keywords": ["lottery", "winner", "inheritance", "million", "compensation", "fund", "congratulations", "selected", "prize", "investment", "profit", "return", "giveaway", "airdrop", "claim"],
        "score": 25,
        "label": "Too Good To Be True"
    },
    # 3. The "Money" Tactics (The Payload)
    "financial_demand": {
        "keywords": ["gift card", "steam card", "itunes card", "crypto", "bitcoin", "usdt", "ethereum", "wire transfer", "cash app", "deposit", "fee", "payment", "bank transfer", "western union", "moneygram", "routing number", "account number"],
        "score": 40,  # VERY HIGH RISK
        "label": "Financial Coercion"
    },
    # 4. The "Urgency" Tactics (Stop thinking, start acting)
    "urgency": {
        "keywords": ["immediately", "urgent", "24 hours", "48 hours", "today", "now", "expires", "deadline", "act now", "hurry", "asap", "final notice", "warning"],
        "score": 20,
        "label": "Artificial Urgency"
    },
    # 5. The "Authority" Tactics (Impersonation)
    "impersonation": {
        "keywords": ["microsoft support", "windows support", "apple support", "amazon support", "paypal support", "geek squad", "technical department", "fraud department", "security team", "manager", "ceo", "government", "official"],
        "score": 25,
        "label": "Authority Impersonation"
    },
    # 6. The "Action" Tactics (Luring off-platform)
    "call_to_action": {
        "keywords": ["call us", "call this number", "contact support", "click the link", "click here", "verify your identity", "log in", "update account", "fill this form", "reply", "kindly"],
        "score": 15,
        "label": "Suspicious Call-to-Action"
    },
    # 7. Remote Access Tools (CRITICAL for Tech Support Scams)
    "remote_access": {
        "keywords": ["anydesk", "teamviewer", "ultraviewer", "zoho", "connectwise", "support client", "run", "execute"],
        "score": 50, # EXTREME RISK
        "label": "Remote Access Tool (RAT) Request"
    }
}

@app.route('/')
def home():
    return "Sentinal Brain is Active & Bulletproof 🟢"

@app.route('/analyze', methods=['POST'])
def analyze_intent():
    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data.get('text', '').lower()
    
    score = 0
    detected_tactics = []
    
    # --- PHASE 1: PATTERN RECOGNITION (REGEX) ---
    # Detect Phone Numbers (Tech Support Scams usually include these)
    phone_pattern = re.compile(r'(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}')
    if phone_pattern.search(text):
        score += 20
        detected_tactics.append({
            "tactic": "Unsolicited Contact Info",
            "description": "Contains a phone number. Legitimate companies rarely ask you to call a random number in a text.",
            "icon": "bi-telephone-x-fill"
        })

    # Detect Links (Phishing)
    link_pattern = re.compile(r'(http|https|www\.|bit\.ly|tinyurl)')
    if link_pattern.search(text):
        score += 20
        detected_tactics.append({
            "tactic": "Suspicious Link",
            "description": "Contains a direct link. Scammers use these to steal passwords.",
            "icon": "bi-link-45deg"
        })

    # --- PHASE 2: ADVANCED KEYWORD ANALYSIS ---
    for category, details in THREAT_INDICATORS.items():
        # Find all matching keywords in the text
        found_words = [word for word in details['keywords'] if word in text]
        
        if found_words:
            # Add score (once per category to prevent double counting)
            score += details['score']
            
            # Create a detailed report
            detected_tactics.append({
                "tactic": details['label'],
                "description": f"Triggered by words like: '{', '.join(found_words[:3])}'",
                "icon": "bi-shield-exclamation"
            })

    # --- PHASE 3: SENTIMENT ANALYSIS ---
    blob = TextBlob(text)
    
    # CASE A: High Fear (Negative Polarity)
    if blob.sentiment.polarity < -0.3 and score > 0:
        score += 10
        detected_tactics.append({
            "tactic": "Negative Emotional Manipulation",
            "description": "Uses negative language to create fear or panic.",
            "icon": "bi-emoji-frown-fill"
        })
        
    # CASE B: The "Kindly" Trap (Polite + Demand)
    if "kindly" in text and blob.sentiment.polarity > 0.1:
        score += 15
        detected_tactics.append({
            "tactic": "Calculated Politeness",
            "description": "Uses overly formal/polite language ('kindly') to lower defenses.",
            "icon": "bi-chat-heart-fill"
        })

    # --- PHASE 4: FINAL VERDICT ---
    final_score = min(score, 100)

    verdict = "Safe"
    if final_score > 30: verdict = "Suspicious"
    if final_score > 60: verdict = "High Risk"
    if final_score > 85: verdict = "DANGEROUS"

    # Provide Specific Advice based on findings
    advice = "No obvious threats found. Always verify the sender."
    if final_score > 30: advice = "Be careful. Verify the source independently."
    if final_score > 60: advice = "Do not click links. Do not call numbers. Block sender."
    if final_score > 85: advice = "CRITICAL: This is a scam. Delete immediately."

    return jsonify({
        "score": final_score,
        "verdict": verdict,
        "tactics": detected_tactics,
        "advice": advice
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
