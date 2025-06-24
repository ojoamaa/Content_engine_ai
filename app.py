# --- THE FINAL, CORRECTED APP.PY ---

import os, json, re, datetime, hashlib, hmac, base64, io
from datetime import timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort
from dotenv import load_dotenv
import google.generativeai as genai
import google.api_core.exceptions
import requests 
from dateutil.parser import isoparse
import stability_sdk.interfaces.gooseai.generation.generation_pb2 as generation
from stability_sdk import client
import vertexai
from vertexai.preview.vision_models import ImageGenerationModel
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm 

load_dotenv()
app = Flask(__name__)

# --- Configuration ---
IMAGE_PROVIDER = "STABILITY" 
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or 'v2_debug_route_secret_CHANGE_ME_PLEASE'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///site.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PAYSTACK_SECRET_KEY'] = os.environ.get('PAYSTACK_SECRET_KEY')

# --- Service Initializations ---
gemini_model, stability_api = None, None
try:
    PROJECT_ID, LOCATION = "content-engine-ai", "us-central1"
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    print("Vertex AI Initialized Successfully")
except Exception as e: print(f"Error initializing Vertex AI: {e}")
try:
    STABILITY_API_KEY = os.environ.get("STABILITY_API_KEY")
    if STABILITY_API_KEY:
        stability_api = client.StabilityInference(key=STABILITY_API_KEY, verbose=True, engine="stable-diffusion-xl-1024-v1-0")
        print("Stability AI Client Initialized Successfully")
    else: print("Warning: STABILITY_API_KEY not found.")
except Exception as e: print(f"Error initializing Stability AI client: {e}")
try:
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key: print("Warning: GEMINI_API_KEY not found.")
    else:
        genai.configure(api_key=gemini_api_key)
        gemini_model = genai.GenerativeModel('gemini-1.5-flash-latest')
        print("Gemini API Client Initialized Successfully")
except Exception as e: print(f"Error configuring Gemini API: {e}")

# --- App Globals & DB Setup ---
FOUNDER_PACKS_CLAIMED = 0 
MAX_FOUNDER_PACKS = 20
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'
login_manager.login_message = "Please log in to access this page."
 
# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) 
    username = db.Column(db.String(80), unique=True, nullable=True) 
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    subscription_tier = db.Column(db.String(50), default='free', nullable=False) 
    subscription_status = db.Column(db.String(50), default='active', nullable=False) 
    paystack_customer_code = db.Column(db.String(100), nullable=True)
    paystack_subscription_code = db.Column(db.String(100), nullable=True)
    free_generations_used = db.Column(db.Integer, default=0, nullable=False)
    monthly_generations_allowed = db.Column(db.Integer, default=10, nullable=False) 
    monthly_generations_used = db.Column(db.Integer, default=0, nullable=False)
    current_period_end = db.Column(db.DateTime, nullable=True)
    is_founder = db.Column(db.Boolean, default=False, nullable=False)
    def __repr__(self): return f"User('{self.email}', Tier: '{self.subscription_tier}')"
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class GeneratedContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    caption_text = db.Column(db.Text, nullable=False)
    visual_suggestion = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    user = db.relationship('User', backref=db.backref('generated_contents', lazy=True))
    def __repr__(self): return f"GeneratedContent(user_id={self.user_id}, created_at='{self.created_at}')"
 
@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))
 
@app.context_processor
def inject_now(): return {'now': datetime.datetime.now(timezone.utc)}
 
@app.context_processor 
def inject_founder_pack_status():
    global FOUNDER_PACKS_CLAIMED, MAX_FOUNDER_PACKS
    return dict(founder_packs_available=(FOUNDER_PACKS_CLAIMED < MAX_FOUNDER_PACKS), founder_packs_remaining=(MAX_FOUNDER_PACKS - FOUNDER_PACKS_CLAIMED))
 
def construct_local_biz_caption_prompt(data):
    num_variations = int(data.get('numVariations', 3))
    business_name = data.get('businessName') or "Our business"
    business_type = data.get('businessType', 'local business')
    post_type = data.get('postType', 'general announcement').replace('_', ' ')
    key_message = data.get('keyMessage', 'something exciting!')
    target_audience = data.get('targetAudience')
    tone = data.get('tone', 'friendly & casual').replace('_', ' ')
    call_to_action = data.get('callToAction', 'no specific cta')
    include_emojis = data.get('includeEmojis') == 'on'
    prompt_lines = [f"You are an expert social media manager.", f"Generate {num_variations} distinct social media caption variations.", f"It is critical that you provide exactly {num_variations} variations. Do not provide fewer."]
    if business_name != "Our business": prompt_lines.append(f"The business name is '{business_name}'.")
    if target_audience: prompt_lines.append(f"The primary target audience: '{target_audience}'. Tailor language accordingly.")
    if call_to_action != "no specific cta" and call_to_action != "custom_cta":
        cta_text_map = {"visit_us": "Visit Us Today!", "shop_now_online": "Shop Now/Order Online!", "book_appointment_now": "Book Your Appointment Now!", "learn_more": "Learn More (link in bio/DM us)!", "tag_friend": "Tag a Friend Who Needs This!", "contact_us": "Contact Us for Details!"}
        cta_text = cta_text_map.get(call_to_action, call_to_action.replace('_', ' ').title() + "!")
        prompt_lines.append(f"Include a call to action like: '{cta_text}'.")
    elif call_to_action == "custom_cta": prompt_lines.append("Infer a custom call to action from the key message.")
    if include_emojis: prompt_lines.append("Include relevant emojis.")
    else: prompt_lines.append("Do not use emojis.")
    prompt_lines.extend(["Instructions for the AI:", f"- Tailor each caption specifically to a '{business_type}' and its target audience.", "- Each caption must be a complete thought.", "- After each caption, on a new line, add 'Visual Suggestion:'.", "- Ensure each complete variation (caption + Visual Suggestion) is separated by a TRIPLE newline (two blank lines).", "- No introductory/concluding remarks or labels like 'Caption 1:'."])
    return "\n".join(prompt_lines)

def construct_artisan_description_prompt(data):
    num_variations = int(data.get('numVariations', 2))
    creator_name = data.get('creatorName')
    product_name = data.get('productName', 'this unique item')
    product_category = data.get('productCategory', 'handmade product')
    key_materials = data.get('keyMaterials', 'quality materials')
    inspiration = data.get('inspiration')
    unique_selling_points = data.get('uniqueSellingPoints', 'it is special')
    prompt_lines = [ f"You are an expert copywriter for artisans.", f"Generate {num_variations} distinct product description variations.", f"It is critical that you provide exactly {num_variations} variations. Do not provide fewer.", f"Product: '{product_name}', Type: '{product_category}'.", f"Materials: '{key_materials}'.", f"USPs/Benefits: '{unique_selling_points}'.", ]
    if creator_name: prompt_lines.append(f"Creator: '{creator_name}'.")
    if inspiration: prompt_lines.append(f"Inspiration: '{inspiration}'.")
    prompt_lines.extend(["Instructions for AI:", f"- Write evocative descriptions for a handmade '{product_category}'.", "- Emphasize craftsmanship, materials, story/inspiration.", "- Suitable for online shop. 1-2 paragraphs each.", "- After each description, on a new line, add 'Visual Suggestion:'.", "- Ensure each complete variation (description + Visual Suggestion) is separated by a TRIPLE newline (two blank lines).", "- No introductory/concluding remarks or labels."])
    return "\n".join(prompt_lines)

def parse_ai_response_into_blocks(generated_text, num_variations_requested):
    if not generated_text: return []
    blocks, all_variations, suggestion_marker = re.split(r'\n\s*\n\s*\n', generated_text.strip()), [], "Visual Suggestion:"
    for block in blocks:
        if not block.strip(): continue
        main_content, visual_suggestion = block.strip(), ""
        marker_pos = block.find(suggestion_marker)
        if marker_pos != -1:
            main_content, visual_suggestion = block[:marker_pos].strip(), block[marker_pos:].strip()
        all_variations.append({"main_content": main_content, "visual_suggestion": visual_suggestion})
        if len(all_variations) == num_variations_requested: break
    return all_variations

@app.route('/')
def index(): return render_template('index.html', title="Home")

@app.route('/history')
@login_required
def history():
    user_history = GeneratedContent.query.filter_by(user_id=current_user.id).order_by(GeneratedContent.created_at.desc()).all()
    return render_template('history.html', title='My Content History', history=user_history)
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index')) 
    form = RegistrationForm()
    if form.validate_on_submit(): 
        existing_user_email = User.query.filter_by(email=form.email.data).first()
        if existing_user_email:
            flash('That email address is already registered. Please log in.', 'danger'); return redirect(url_for('register')) 
        if form.username.data:
            existing_user_username = User.query.filter_by(username=form.username.data).first()
            if existing_user_username:
                flash('That username is already taken. Please choose a different one.', 'danger'); return redirect(url_for('register'))
        hashed_password = generate_password_hash(form.password.data)
        user = User(email=form.email.data, username=form.username.data or None, password_hash=hashed_password)
        db.session.add(user); db.session.commit()
        flash('Your account has been created! You can now log in.', 'success'); return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data); flash('Login successful!', 'success')
            next_page = request.args.get('next'); return redirect(next_page) if next_page else redirect(url_for('index'))
        else: flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required 
def logout(): logout_user(); flash('You have been logged out.', 'info'); return redirect(url_for('index'))

@app.route('/account')
@login_required
def account(): return render_template('account.html', title='My Account') 

@app.route('/pricing') 
def pricing(): return render_template('pricing.html', title='Pricing') 

PAYSTACK_BASE_URL = 'https://api.paystack.co'
PAYSTACK_PLAN_CODES = { "standard": os.environ.get("PAYSTACK_STANDARD_PLAN_CODE"), "premium": os.environ.get("PAYSTACK_PREMIUM_PLAN_CODE"), "founder": os.environ.get("PAYSTACK_FOUNDER_PACK_CODE") }
TIER_DETAILS = { "founder": {"name": "Founder's Pack", "generations": 150, "duration_days": 90, "price_kobo": 100000, "is_recurring": True}, "standard": {"name": "Standard", "generations": 50, "price_kobo": 100000, "is_recurring": True}, "premium": {"name": "Premium", "generations": 150, "price_kobo": 150000, "is_recurring": True} }
 
@app.route('/subscribe/<tier_key>')
@login_required
def subscribe(tier_key):
    global FOUNDER_PACKS_CLAIMED, MAX_FOUNDER_PACKS 
    if tier_key not in TIER_DETAILS: flash("Invalid subscription plan selected.", "danger"); return redirect(url_for('pricing'))
    tier_info = TIER_DETAILS[tier_key]
    if tier_key == "founder" and (current_user.is_founder or current_user.subscription_tier == 'founder'):
        flash("You have already claimed or have an active Founder's Pack.", "info"); return redirect(url_for('account'))
    if tier_key == "founder" and FOUNDER_PACKS_CLAIMED >= MAX_FOUNDER_PACKS:
        flash("Sorry, all Founder's Packs have been claimed.", "info"); return redirect(url_for('pricing'))
    headers = {"Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}", "Content-Type": "application/json"}
    callback_url = url_for('paystack_callback', _external=True)
    reference = f"user{current_user.id}_{tier_key}_{int(datetime.datetime.now().timestamp())}"
    payload = {"email": current_user.email, "callback_url": callback_url, "reference": reference, "metadata": { "user_id": current_user.id, "tier_key": tier_key, "plan_code_used": PAYSTACK_PLAN_CODES.get(tier_key), "custom_fields": [ {"display_name": "User ID", "variable_name": "user_id", "value": str(current_user.id)}, {"display_name": "Selected Plan Name", "variable_name": "selected_plan_name", "value": tier_info["name"]} ] } }
    if tier_info["is_recurring"] and PAYSTACK_PLAN_CODES.get(tier_key): payload['plan'] = PAYSTACK_PLAN_CODES[tier_key]
    else: payload['amount'] = tier_info["price_kobo"]
    if current_user.paystack_customer_code: payload['customer'] = current_user.paystack_customer_code
    try:
        response = requests.post(f"{PAYSTACK_BASE_URL}/transaction/initialize", headers=headers, json=payload)
        response.raise_for_status(); paystack_response = response.json()
        if paystack_response.get("status"): return redirect(paystack_response["data"]["authorization_url"])
        else: flash(f"Paystack: {paystack_response.get('message', 'Error')}", "danger"); return redirect(url_for('account'))
    except Exception as e: flash(f"Payment gateway error.", "danger"); print(f"Paystack Error: {e}"); return redirect(url_for('account'))

@app.route('/paystack_callback')
@login_required 
def paystack_callback():
    reference = request.args.get('trxref') or request.args.get('reference')
    if not reference: flash("Payment reference missing.", "danger"); return redirect(url_for('index')) 
    headers = { "Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}" }
    try:
        response = requests.get(f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}", headers=headers)
        response.raise_for_status(); verification_data = response.json()
        if verification_data.get("status") and verification_data["data"]["status"] == "success":
            payment_data = verification_data["data"]; customer_data = payment_data.get("customer", {})
            metadata = payment_data.get("metadata", {}); user_id_from_meta = metadata.get("user_id") if isinstance(metadata, dict) else None
            if not user_id_from_meta or str(current_user.id) != str(user_id_from_meta):
                flash("Payment verification user mismatch.", "danger"); return redirect(url_for('index'))
            tier_key = metadata.get("tier_key") if isinstance(metadata, dict) else None
            if tier_key and tier_key in TIER_DETAILS:
                tier_info = TIER_DETAILS[tier_key]
                current_user.subscription_tier = tier_key; current_user.subscription_status = 'active'
                current_user.paystack_customer_code = customer_data.get("customer_code", current_user.paystack_customer_code)
                current_user.monthly_generations_allowed = tier_info["generations"]
                current_user.monthly_generations_used = 0; current_user.free_generations_used = 10 
                if tier_key == "founder":
                    global FOUNDER_PACKS_CLAIMED, MAX_FOUNDER_PACKS 
                    if FOUNDER_PACKS_CLAIMED < MAX_FOUNDER_PACKS and not current_user.is_founder:
                        current_user.is_founder = True
                        current_user.current_period_end = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=tier_info["duration_days"])
                        FOUNDER_PACKS_CLAIMED += 1 
                        print(f"Founder pack applied for user {current_user.email}. Count: {FOUNDER_PACKS_CLAIMED}")
                    else: flash("Founder pack could not be applied.", "warning"); return redirect(url_for('account'))
                else: 
                    current_user.is_founder = False 
                    current_user.paystack_subscription_code = payment_data.get("subscription", {}).get("subscription_code")
                    current_user.current_period_end = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=30) 
                db.session.commit(); flash(f"Your {tier_info['name']} access has been activated!", "success")
            else: flash("Subscription plan details unclear. Contact support.", "warning")
            return redirect(url_for('account'))
        else:
            flash(f"Paystack payment not successful: {verification_data.get('data', {}).get('gateway_response', 'Unknown reason')}", "danger"); return redirect(url_for('account'))
    except Exception as e:
        flash(f"Payment verification error. Contact support.", "danger"); print(f"Paystack Callback Error: {e}"); return redirect(url_for('account'))
 
@app.route('/paystack_webhook', methods=['POST'])
def paystack_webhook():
    paystack_secret = app.config['PAYSTACK_SECRET_KEY']
    signature = request.headers.get('X-Paystack-Signature')
    payload_body = request.data
    if not signature or not paystack_secret: print("Webhook Error: Missing signature or secret key."); abort(400) 
    hash_obj = hmac.new(paystack_secret.encode('utf-8'), payload_body, hashlib.sha512); expected_signature = hash_obj.hexdigest()
    if not hmac.compare_digest(expected_signature, signature): print("Webhook Error: Invalid signature."); abort(400) 
    event_data_full = request.get_json(); event_type = event_data_full.get('event'); data = event_data_full.get('data', {})
    print(f"Webhook received: {event_type}"); user = None; customer_data = data.get('customer', {})
    if customer_data:
        customer_email = customer_data.get('email')
        if customer_email: user = User.query.filter_by(email=customer_email).first()
    if not user:
        sub_code_event = data.get('subscription_code')
        if sub_code_event: user = User.query.filter_by(paystack_subscription_code=sub_code_event).first()
        if not user: print(f"Webhook: User not found."); return jsonify({"status": "success"}), 200
    if user:
        if event_type == 'subscription.disable':
            event_sub_code = data.get('subscription_code')
            if user.paystack_subscription_code == event_sub_code:
                user.subscription_status = 'inactive'; user.is_founder = False
                db.session.commit(); print(f"Subscription for {user.email} disabled by webhook.")
            else: print(f"Webhook {event_type}: sub_code mismatch.")
    return jsonify({"status": "success"}), 200

@app.route('/generate_local_biz_captions', methods=['POST'])
@login_required 
def generate_local_biz_captions():
    if current_user.subscription_status != 'active': return jsonify({"error": "Subscription not active. Check account."}), 403
    used_field = 'monthly_generations_used'
    allowed_generations = current_user.monthly_generations_allowed
    if getattr(current_user, used_field) >= allowed_generations:
        return jsonify({"error": f"Your monthly generation limit ({allowed_generations}) reached."}), 403
    if not gemini_model: return jsonify({"error": "Gemini API model not configured."}), 500
    try:
        data = request.get_json()
        prompt = construct_local_biz_caption_prompt(data)
        num_variations = int(data.get('numVariations', 3))
        print("Generating text...")
        try:
            request_options = {"timeout": 60} 
            response = gemini_model.generate_content(prompt, request_options=request_options)
            parsed_items = parse_ai_response_into_blocks(response.text, num_variations)
        except google.api_core.exceptions.DeadlineExceeded:
            return jsonify({"error": "Connection to the text AI timed out. Please try again."}), 504
        valid_items = [p for p in parsed_items if p.get("main_content")]
        print(f"Generated {len(valid_items)} valid items.")
        payload = {"captions": valid_items, "image_data": None}
        if valid_items:
            image_data_string = None
            if IMAGE_PROVIDER == "STABILITY" and stability_api:
                print("Generating image with Stability AI...")
                first_item_text = valid_items[0].get("main_content")
                image_prompt = f"A vibrant, eye-catching social media marketing image for a '{data.get('businessType', '')}', style of hyper-realistic 3D render. The image should represent: {first_item_text}"
                answers = stability_api.generate(prompt=image_prompt, steps=30, cfg_scale=7.0, width=1024, height=1024, samples=1)
                for resp in answers:
                    for artifact in resp.artifacts:
                        if artifact.type == generation.ARTIFACT_IMAGE:
                            image_data_string = base64.b64encode(artifact.binary).decode('utf-8')
                            print("Image generated successfully with Stability AI.")
                            break
                    if image_data_string: break
            payload["image_data"] = image_data_string
            print(f"Saving {len(valid_items)} content items to history...")
            for item in valid_items:
                db.session.add(GeneratedContent(user_id=current_user.id, caption_text=item.get("main_content"), visual_suggestion=item.get("visual_suggestion")))
        setattr(current_user, used_field, getattr(current_user, used_field) + 1)
        db.session.commit()
        print("History and usage count saved to DB.")
        return jsonify(payload)
    except Exception as e:
        error_string = str(e).lower()
        error_message = f"An internal error occurred: {str(e)}"
        status_code = 500
        if "timed out" in error_string or "unavailable" in error_string:
            error_message = "The connection to the AI service timed out. Please try again."
            status_code = 504
        print(f"Error during generation: {e}")
        return jsonify({"error": error_message}), status_code

@app.route('/generate_artisan_description', methods=['POST'])
@login_required 
def generate_artisan_description():
    if current_user.subscription_tier == 'standard': return jsonify({"error": "Artisan tool requires a higher plan."}), 403
    if current_user.subscription_status != 'active': return jsonify({"error": "Subscription not active. Check account."}), 403
    used_field = 'monthly_generations_used'
    allowed_generations = current_user.monthly_generations_allowed
    if getattr(current_user, used_field) >= allowed_generations:
        return jsonify({"error": f"Your monthly generation limit ({allowed_generations}) reached."}), 403
    if not gemini_model: return jsonify({"error": "Gemini API model not configured."}), 500
    try:
        data = request.get_json()
        prompt = construct_artisan_description_prompt(data)
        num_variations = int(data.get('numVariations', 2))
        print("Generating text...")
        try:
            request_options = {"timeout": 60} 
            response = gemini_model.generate_content(prompt, request_options=request_options)
            parsed_items = parse_ai_response_into_blocks(response.text, num_variations)
        except google.api_core.exceptions.DeadlineExceeded:
            return jsonify({"error": "Connection to the text AI timed out. Please try again."}), 504
        valid_items = [p for p in parsed_items if p.get("main_content")]
        print(f"Generated {len(valid_items)} valid items.")
        payload = {"descriptions": valid_items, "image_data": None}
        if valid_items:
            image_data_string = None
            if IMAGE_PROVIDER == "STABILITY" and stability_api:
                print("Generating image with Stability AI...")
                first_item_text = valid_items[0].get("main_content")
                image_prompt = f"A beautiful, high-quality product shot suitable for social media. The product is a '{data.get('productCategory', '')}'. The style should reflect: {first_item_text}"
                answers = stability_api.generate(prompt=image_prompt, steps=30, cfg_scale=7.0, width=1024, height=1024, samples=1)
                for resp in answers:
                    for artifact in resp.artifacts:
                        if artifact.type == generation.ARTIFACT_IMAGE:
                            image_data_string = base64.b64encode(artifact.binary).decode('utf-8')
                            print("Image generated successfully with Stability AI.")
                            break
                    if image_data_string: break
            payload["image_data"] = image_data_string
            print(f"Saving {len(valid_items)} content items to history...")
            for item in valid_items:
                db.session.add(GeneratedContent(user_id=current_user.id, caption_text=item.get("main_content"), visual_suggestion=item.get("visual_suggestion")))
        setattr(current_user, used_field, getattr(current_user, used_field) + 1)
        db.session.commit()
        print("History and usage count saved to DB.")
        return jsonify(payload)
    except Exception as e:
        error_string = str(e).lower()
        error_message = f"An internal error occurred: {str(e)}"
        status_code = 500
        if "timed out" in error_string or "unavailable" in error_string:
            error_message = "The connection to the AI service timed out. Please try again."
            status_code = 504
        print(f"Error during generation: {e}")
        return jsonify({"error": error_message}), status_code

if __name__ == '__main__':
    with app.app_context():
        try:
            if db.engine.dialect.has_table(db.engine.connect(), User.__tablename__):
                FOUNDER_PACKS_CLAIMED = User.query.filter_by(is_founder=True).count()
                print(f"Initialized Founder Packs Claimed from DB: {FOUNDER_PACKS_CLAIMED}")
            else:
                print("User table not found on startup. FOUNDER_PACKS_CLAIMED set to 0.")
                FOUNDER_PACKS_CLAIMED = 0
        except Exception as e_init:
            print(f"Error initializing founder pack count from DB: {e_init}")
            FOUNDER_PACKS_CLAIMED = 0 
    app.run(debug=True, port=5000)