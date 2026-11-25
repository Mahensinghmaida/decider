import hashlib
import hmac
import os
import random
import time

from flask import Flask, jsonify, request

app = Flask(__name__)
SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]


def verified(req) -> bool:
    """Check the request really came from Slack (HMAC-SHA256 signature)."""
    ts = req.headers.get("X-Slack-Request-Timestamp", "0")
    sig = req.headers.get("X-Slack-Signature", "")
    if abs(time.time() - int(ts)) > 300:  # replay protection
        return False
    base = f"v0:{ts}:{req.get_data(as_text=True)}".encode()
    expected = "v0=" + hmac.new(SIGNING_SECRET.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


@app.get("/")
def health():
    return "Decider is running"


@app.post("/slack/decide")
def decide():
    if not verified(request):
        return "invalid signature", 401

    text = request.form.get("text", "").strip()
    user = request.form.get("user_id")
    options = [o.strip() for o in text.split(",") if o.strip()]

    if len(options) < 2:
        # Only visible to the caller
        return jsonify(
            response_type="ephemeral",
            text="Give me at least two options, e.g. `/decide pizza, tacos, sushi`",
        )

    pick = random.choice(options)
    return jsonify(
        response_type="in_channel",  # posts to the whole channel
        text=f"<@{user}> asked me to choose between: {', '.join(options)}\n:game_die: I pick *{pick}*!",
    )


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 3000)))
