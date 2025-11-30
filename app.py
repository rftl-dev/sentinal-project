from flask import Flask, request, jsonify
from flask_cors import CORS
from textblob import TextBlob
from thefuzz import fuzz
import re

app = Flask(__name__)
CORS(app) 

# --- 1. CONCEPT DATABASE (Keywords) ---
THREAT_INDICATORS = {
    "high_fear": {
        "keywords": ["virus", "infected", "hacked", "breach", "compromised", "suspended", "locked", "banned", "deactivated", "warrant", "arrest", "legal action", "police", "fbi", "irs", "lawsuit", "trojan", "malware", "spyware"],
        "score": 30, "label": "Fear Mongering"
    },
    "high_greed": {
        "keywords": ["lottery", "winner", "inheritance", "million", "compensation", "fund", "congratulations", "selected", "prize", "investment", "profit", "return", "giveaway", "airdrop", "claim"],
        "score": 25, "label": "Too Good To Be True"
    },
    "financial_demand": {
        "keywords": ["gift card", "steam card", "itunes card", "crypto", "bitcoin", "usdt", "ethereum", "wire transfer", "cash app", "deposit", "fee", "payment", "bank transfer", "western union", "moneygram", "routing number", "account number"],
        "score": 40, "label": "Financial Coercion"
    },
    "sensitive_data": {
        "keywords": ["bank details", "credit card", "debit card", "password", "pin number", "cvv", "ssn", "social security", "credential", "login info", "card number", "mother's maiden name", "passport"],
        "score": 50, "label": "Data Theft / PII Request"
    },
    "urgency": {
        "keywords": ["immediately", "urgent", "24 hours", "48 hours", "today", "now", "expires", "deadline", "act now", "hurry", "asap", "final notice", "warning", "at once"],
        "score": 20, "label": "Artificial Urgency"
    },
    "impersonation": {
        "keywords": ["microsoft support", "windows support", "apple support", "amazon support", "paypal support", "geek squad", "technical department", "fraud department", "security team", "manager", "ceo", "government", "official", "agent"],
        "score": 25, "label": "Authority Impersonation"
    },
    "call_to_action": {
        "keywords": ["call us", "call this number", "contact support", "click the link", "click here", "verify your identity", "log in", "update account", "fill this form", "reply", "kindly", "via this link", "open the link", "visit the link", "download"],
        "score": 15, "label": "Suspicious Call-to-Action"
    }
}

KNOWN_SCAM_PHRASES = [
    "kindly deposit the money", "share your bank details", "click the link below to verify",
    "send me the code", "i need your help urgently", "you have won a prize",
    "your account has been locked", "verify your wallet", "send it via this link",
    "fill out the form below", "contact me immediately"
]

def calculate_perplexity(text):
    """
    Advanced Heuristic for AI Detection.
    Checks for 'Robot Voice' features: Low subjectivity, formal transitions, and perfect grammar.
    """
    blob = TextBlob(text)
    words = text.split()
    if not words: return 0
    
    ai_score = 0

    # 1. Subjectivity Check (AI is often purely objective/factual)
    # Humans usually have opinions (Subjectivity > 0.5). AI is often 0.0 - 0.3.
    if blob.sentiment.subjectivity < 0.4:
        ai_score += 30

    # 2. The "Transition Word" Trap
    # AI loves these words in short texts. Humans rarely use "Furthermore" in a DM.
    robotic_transitions = ["furthermore", "moreover", "in conclusion", "additionally", "consequently", "hence", "thus", "therefore"]
    found_transitions = [w for w in robotic_transitions if w in text.lower()]
    
    if len(found_transitions) > 0:
        ai_score += 40  # Huge red flag for AI

    # 3. Sentence Structure Uniformity
    # AI writes sentences of similar length. Humans vary wildly.
    sentences = blob.sentences
    if len(sentences) > 2:
        lengths = [len(s.words) for s in sentences]
        avg_len = sum(lengths) / len(lengths)
        # Check if variance is low (all sentences are roughly average length)
        variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
        if variance < 10: # Low variance = Robotic rhythm
            ai_score += 20

    return min(ai_score, 100)

@app.route('/')
def home():
    return "Sentinal Brain is Active & Context-Aware 🟢"

@app.route('/analyze', methods=['POST'])
def analyze_intent():
    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data.get('text', '').lower()
    
    score = 0
    detected_tactics = []
    found_categories = [] 

    # --- PHASE 1: REGEX PATTERNS ---
    phone_pattern = re.compile(r'(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}')
    if phone_pattern.search(text):
        score += 20
        detected_tactics.append({"tactic": "Unsolicited Contact Info", "description": "Contains a phone number.", "icon": "bi-telephone-x-fill"})
        found_categories.append("phone")

    link_pattern = re.compile(r'(http|https|www\.|bit\.ly|tinyurl)')
    if link_pattern.search(text):
        score += 20
        detected_tactics.append({"tactic": "Suspicious Link", "description": "Contains a direct link.", "icon": "bi-link-45deg"})
        found_categories.append("link")

    # --- PHASE 2: FUZZY KEYWORD MATCHING ---
    FUZZY_THRESHOLD = 85
    for category, details in THREAT_INDICATORS.items():
        matches = []
        for keyword in details['keywords']:
            if fuzz.partial_ratio(keyword, text) >= FUZZY_THRESHOLD:
                matches.append(keyword)
        
        if matches:
            score += details['score']
            found_categories.append(category)
            detected_tactics.append({
                "tactic": details['label'],
                "description": f"Detected concepts similar to '{matches[0]}'",
                "icon": "bi-shield-exclamation"
            })

    # --- PHASE 3: SEMANTIC PHRASE MATCHING ---
    for phrase in KNOWN_SCAM_PHRASES:
        ratio = fuzz.token_set_ratio(phrase, text)
        if ratio > 80: 
            score += 30
            detected_tactics.append({
                "tactic": "Scam Script Match",
                "description": f"Sentence structure matches known scams (Similarity: {ratio}%).",
                "icon": "bi-file-earmark-text-fill"
            })
            break

    # --- PHASE 4: CONTEXTUAL LOGIC ---
    if "sensitive_data" in found_categories and ("link" in found_categories or "call_to_action" in found_categories):
        score += 40
        detected_tactics.append({
            "tactic": "Phishing Pattern Detected",
            "description": "CRITICAL: Asking for sensitive info via a link.",
            "icon": "bi-radioactive"
        })

    if "financial_demand" in found_categories and "urgency" in found_categories:
        score += 30
        detected_tactics.append({
            "tactic": "Coercion Pattern Detected",
            "description": "Combines financial demands with artificial urgency.",
            "icon": "bi-stopwatch-fill"
        })

    # --- PHASE 5: AI & SENTIMENT ANALYSIS ---
    blob = TextBlob(text)
    
    if "kindly" in text and blob.sentiment.polarity > 0.1:
        score += 15
        detected_tactics.append({"tactic": "Calculated Politeness", "description": "Uses 'kindly' to lower defenses.", "icon": "bi-chat-heart-fill"})

    # AI Detection Check
    ai_probability = calculate_perplexity(request.json['text']) # Pass ORIGINAL text for structure analysis
    if ai_probability > 50:
        detected_tactics.append({
            "tactic": "AI-Generated Pattern",
            "description": f"Writing style is highly formal/objective (Score: {ai_probability}%). Likely Bot/AI.",
            "icon": "bi-robot"
        })

    # --- PHASE 6: FINAL VERDICT ---
    final_score = min(score, 100)
    verdict = "Safe"
    advice = "No obvious threats found."
    
    if final_score > 30: 
        verdict = "Suspicious"
        advice = "Be careful. Verify the source independently."
    if final_score > 70: 
        verdict = "Malicious"
        advice = "CRITICAL: High probability of a scam. Do not click or reply."

    return jsonify({
        "score": final_score,
        "verdict": verdict,
        "tactics": detected_tactics,
        "advice": advice,
        "ai_score": ai_probability
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
