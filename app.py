import os
import json
import re 
import datetime
import hashlib 
import hmac    
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort
from dotenv import load_dotenv
import google.generativeai as genai
import requests 
from dateutil.parser import isoparse # For parsing ISO 8601 date strings from Paystack

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from forms import RegistrationForm, LoginForm 

load_dotenv()
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or 'v2_webhook_secret_CHANGE_ME_PLEASE_FINAL_AGAIN_2' # IMPORTANT
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///site.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PAYSTACK_SECRET_KEY'] = os.environ.get('PAYSTACK_SECRET_KEY') 

# --- Global Variables for Founder's Pack (MVP approach) ---
# For better persistence, especially with multiple workers or app restarts, 
# this counter should ideally be stored and managed in the database.
# An 'AppSettings' table with a key-value pair could work.
FOUNDER_PACKS_CLAIMED = 0 
MAX_FOUNDER_PACKS = 20 

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'
login_manager.login_message = "Please log in to access this page."

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) 
    username = db.Column(db.String(80), unique=True, nullable=True) 
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
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

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

@app.context_processor
def inject_now(): return {'now': datetime.datetime.now(datetime.UTC)}

@app.context_processor 
def inject_founder_pack_status():
    global FOUNDER_PACKS_CLAIMED 
    # In a production scenario, fetch/update FOUNDER_PACKS_CLAIMED from a persistent store (DB)
    # This global variable will reset on app restart.
    # For example, on app start:
    # with app.app_context(): FOUNDER_PACKS_CLAIMED = User.query.filter_by(is_founder=True).count()
    return dict(
        founder_packs_available=(FOUNDER_PACKS_CLAIMED < MAX_FOUNDER_PACKS),
        founder_packs_remaining=(MAX_FOUNDER_PACKS - FOUNDER_PACKS_CLAIMED)
    )

try:
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key: print("Warning: GEMINI_API_KEY not found.")
    genai.configure(api_key=gemini_api_key)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash-latest')
except Exception as e:
    print(f"Error configuring Gemini API: {e}")
    gemini_model = None

# --- Prompt Construction & Parsing Functions (ensure these are your latest working versions) ---
def construct_local_biz_caption_prompt(data):
    business_name = data.get('businessName') or "Our business"; business_type = data.get('businessType', 'local business')
    post_type = data.get('postType', 'general announcement').replace('_', ' '); key_message = data.get('keyMessage', 'something exciting!')
    target_audience = data.get('targetAudience'); tone = data.get('tone', 'friendly & casual').replace('_', ' ')
    call_to_action = data.get('callToAction', 'no specific cta'); include_emojis = data.get('includeEmojis') == 'on'
    num_variations = int(data.get('numVariations', 3)); prompt_lines = [
        f"You are an expert social media manager.", f"Generate {num_variations} distinct social media caption variations.",
        f"The business type is: '{business_type}'.", f"The desired tone for the caption(s) is '{tone}'.",
        f"The purpose of the post is: '{post_type}'.", f"Key message/details to include: '{key_message}'.",
    ]
    if business_name != "Our business": prompt_lines.append(f"The business name is '{business_name}'.")
    if target_audience: prompt_lines.append(f"The primary target audience: '{target_audience}'. Tailor language accordingly.")
    if call_to_action != "no specific cta" and call_to_action != "custom_cta":
        cta_text_map = {"visit_us": "Visit Us Today!", "shop_now_online": "Shop Now/Order Online!", "book_appointment_now": "Book Your Appointment Now!", "learn_more": "Learn More (link in bio/DM us)!", "tag_friend": "Tag a Friend Who Needs This!", "contact_us": "Contact Us for Details!"}
        cta_text = cta_text_map.get(call_to_action, call_to_action.replace('_', ' ').title() + "!")
        prompt_lines.append(f"Include a call to action like: '{cta_text}'.")
    elif call_to_action == "custom_cta": prompt_lines.append("Infer a custom call to action from the key message.")
    if include_emojis: prompt_lines.append("Include relevant emojis.")
    else: prompt_lines.append("Do not use emojis.")
    prompt_lines.extend([
        "Instructions for the AI:", f"- Tailor each caption specifically to a '{business_type}' and its target audience.",
        "- Each caption must be a complete thought.", "- After each caption, on a new line, add 'Visual Suggestion:'.",
        "- Ensure each complete variation (caption + Visual Suggestion) is separated by a TRIPLE newline (two blank lines).",
        "- No introductory/concluding remarks or labels like 'Caption 1:'."
    ])
    return "\n".join(prompt_lines)

def construct_artisan_description_prompt(data):
    creator_name = data.get('creatorName'); product_name = data.get('productName', 'this unique item')
    product_category = data.get('productCategory', 'handmade product'); key_materials = data.get('keyMaterials', 'quality materials')
    creation_process = data.get('creationProcess'); inspiration = data.get('inspiration')
    unique_selling_points = data.get('uniqueSellingPoints', 'it is special'); target_audience = data.get('targetAudience')
    artisan_tone = data.get('artisanTone', 'story_driven_evocative').replace('_', ' '); num_variations = int(data.get('numVariations', 2))
    prompt_lines = [
        f"You are an expert copywriter for artisans.", f"Generate {num_variations} distinct product description variations.",
        f"Product: '{product_name}', Type: '{product_category}'.", f"Materials: '{key_materials}'.",
        f"Tone: '{artisan_tone}'.", f"USPs/Benefits: '{unique_selling_points}'.",
    ]
    if creator_name: prompt_lines.append(f"Creator: '{creator_name}'.")
    if creation_process: prompt_lines.append(f"Process: '{creation_process}'.")
    if inspiration: prompt_lines.append(f"Inspiration: '{inspiration}'.")
    if target_audience: prompt_lines.append(f"Target audience: '{target_audience}'. Emphasize appeal to them.")
    prompt_lines.extend([
        "Instructions for AI:", f"- Write evocative descriptions for a handmade '{product_category}', considering target audience.",
        "- Emphasize craftsmanship, materials, story/inspiration.", "- Suitable for online shop. 1-2 paragraphs each.",
        "- After each description, on a new line, add 'Visual Suggestion:'.",
        "- Ensure each complete variation (description + Visual Suggestion) is separated by a TRIPLE newline (two blank lines).",
        "- No introductory/concluding remarks or labels."
    ])
    return "\n".join(prompt_lines)

def parse_ai_response_into_blocks(generated_text, num_variations_requested):
    if not generated_text: return []
    lines = [line.strip() for line in generated_text.splitlines()]
    all_complete_variations = []; current_variation_lines = []
    for line_text in lines:
        cleaned_line = line_text.strip()
        if not cleaned_line: continue
        current_variation_lines.append(cleaned_line)
        if cleaned_line.startswith("Visual Suggestion:"):
            if current_variation_lines:
                all_complete_variations.append("\n".join(current_variation_lines))
                current_variation_lines = [] 
                if len(all_complete_variations) == num_variations_requested: break
    if current_variation_lines and len(all_complete_variations) < num_variations_requested:
        all_complete_variations.append("\n".join(current_variation_lines))
    return all_complete_variations[:num_variations_requested] if len(all_complete_variations) > num_variations_requested else all_complete_variations

# --- Auth & Main Routes ---
@app.route('/')
def index(): return render_template('index.html', title="Home")

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
        user.subscription_tier = 'free'; user.monthly_generations_allowed = 10; user.free_generations_used = 0
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

# --- Paystack Integration Routes ---
PAYSTACK_BASE_URL = 'https://api.paystack.co'
PAYSTACK_PLAN_CODES = {
    "standard": os.environ.get("PAYSTACK_STANDARD_PLAN_CODE", "PLN_9szuvkfwec6fq96"), 
    "premium": os.environ.get("PAYSTACK_PREMIUM_PLAN_CODE", "PLN_49wey3rviyo6bp8"),
    "founder": os.environ.get("PAYSTACK_FOUNDER_PACK_CODE", "PLN_lxwft3ddtlakbd6")
}
TIER_DETAILS = {
    "founder": {"name": "Founder's Pack", "generations": 150, "duration_days": 90, "price_kobo": 100000, "is_recurring": True},
    "standard": {"name": "Standard", "generations": 50, "price_kobo": 100000, "is_recurring": True},
    "premium": {"name": "Premium", "generations": 150, "price_kobo": 150000, "is_recurring": True}
}

@app.route('/subscribe/<tier_key>')
@login_required
def subscribe(tier_key):
    global FOUNDER_PACKS_CLAIMED, MAX_FOUNDER_PACKS 
    if tier_key not in TIER_DETAILS:
        flash("Invalid subscription plan selected.", "danger"); return redirect(url_for('pricing'))
    tier_info = TIER_DETAILS[tier_key]
    if tier_key == "founder":
        if current_user.is_founder or current_user.subscription_tier == 'founder':
            flash("You have already claimed or have an active Founder's Pack.", "info"); return redirect(url_for('account'))
        if FOUNDER_PACKS_CLAIMED >= MAX_FOUNDER_PACKS: # Simplistic counter
            flash("Sorry, all Founder's Packs have been claimed.", "info"); return redirect(url_for('pricing'))
    # Prevent re-subscribing to same or lower if active
    if tier_key == "standard" and (current_user.subscription_tier == 'standard' or current_user.subscription_tier == 'premium' or current_user.subscription_tier == 'founder') and current_user.subscription_status == 'active':
        flash(f"You are already on the {current_user.subscription_tier} plan or higher.", "info"); return redirect(url_for('account'))
    if tier_key == "premium" and (current_user.subscription_tier == 'premium' or current_user.subscription_tier == 'founder') and current_user.subscription_status == 'active':
        flash(f"You are already on the {current_user.subscription_tier} plan or higher.", "info"); return redirect(url_for('account'))

    headers = {"Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}", "Content-Type": "application/json"}
    callback_url = url_for('paystack_callback', _external=True, _scheme='https')
    reference = f"user{current_user.id}_{tier_key}_{int(datetime.datetime.now().timestamp())}"
    payload = {
        "email": current_user.email, "amount": tier_info["price_kobo"], 
        "callback_url": callback_url, "reference": reference,
        "metadata": {
            "user_id": current_user.id, "tier_key": tier_key,
            "plan_code_used": PAYSTACK_PLAN_CODES.get(tier_key), # Store the plan code if applicable
            "custom_fields": [
                {"display_name": "User ID", "variable_name": "user_id", "value": str(current_user.id)},
                {"display_name": "Selected Plan Name", "variable_name": "selected_plan_name", "value": tier_info["name"]}
            ]
        }
    }
    if tier_info["is_recurring"] and PAYSTACK_PLAN_CODES.get(tier_key):
        payload['plan'] = PAYSTACK_PLAN_CODES[tier_key]
        # For recurring plans, amount might be taken from plan, but Paystack often still requires it in payload
    if current_user.paystack_customer_code: payload['customer'] = current_user.paystack_customer_code
    
    try:
        print(f"Initializing Paystack transaction: {json.dumps(payload)}") # Ensure payload is serializable for print
        response = requests.post(f"{PAYSTACK_BASE_URL}/transaction/initialize", headers=headers, json=payload)
        response.raise_for_status() 
        paystack_response = response.json()
        if paystack_response.get("status"):
            print(f"Redirecting to Paystack: {paystack_response['data']['authorization_url']}")
            return redirect(paystack_response["data"]["authorization_url"])
        else:
            flash(f"Paystack Error: {paystack_response.get('message', 'Could not initialize payment.')}", "danger")
            print(f"Paystack Init Error: {paystack_response.get('message')}")
            return redirect(url_for('account'))
    except requests.exceptions.RequestException as e:
        flash(f"Payment gateway connection error. Please try again later.", "danger")
        print(f"Paystack API Request Error: {e}")
        return redirect(url_for('account'))
    except Exception as e:
        flash(f"An unexpected error occurred during payment setup. Please try again.", "danger")
        print(f"Unexpected Payment Init Error: {e}")
        return redirect(url_for('account'))

@app.route('/paystack_callback')
@login_required 
def paystack_callback():
    reference = request.args.get('trxref') or request.args.get('reference')
    if not reference: flash("Payment reference missing from Paystack.", "danger"); return redirect(url_for('index')) 

    headers = { "Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}" }
    try:
        print(f"Verifying Paystack transaction: {reference}")
        response = requests.get(f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}", headers=headers)
        response.raise_for_status(); verification_data = response.json()
        print(f"Paystack Verification Data: {json.dumps(verification_data, indent=2)}")

        if verification_data.get("status") and verification_data["data"]["status"] == "success":
            payment_data = verification_data["data"]; customer_data = payment_data.get("customer", {})
            metadata = payment_data.get("metadata", {}); 
            user_id_from_meta = metadata.get("user_id") if isinstance(metadata, dict) else None # Check if metadata is dict
            
            if not user_id_from_meta or str(current_user.id) != str(user_id_from_meta):
                flash("Payment verification user mismatch. Contact support.", "danger"); return redirect(url_for('index'))

            tier_key = metadata.get("tier_key") if isinstance(metadata, dict) else None
            
            if tier_key and tier_key in TIER_DETAILS:
                tier_info = TIER_DETAILS[tier_key]
                current_user.subscription_tier = tier_key; current_user.subscription_status = 'active'
                current_user.paystack_customer_code = customer_data.get("customer_code", current_user.paystack_customer_code)
                current_user.monthly_generations_allowed = tier_info["generations"]
                current_user.monthly_generations_used = 0; current_user.free_generations_used = 10 # Max out free uses
                
                if tier_key == "founder":
                    global FOUNDER_PACKS_CLAIMED, MAX_FOUNDER_PACKS 
                    if FOUNDER_PACKS_CLAIMED < MAX_FOUNDER_PACKS and not current_user.is_founder:
                        current_user.is_founder = True
                        current_user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=tier_info["duration_days"])
                        FOUNDER_PACKS_CLAIMED += 1 
                        print(f"Founder pack applied for user {current_user.email}. Count: {FOUNDER_PACKS_CLAIMED}")
                    else: 
                        flash("Founder pack unavailable or already claimed. Contact support.", "warning")
                        return redirect(url_for('account')) # Don't commit if founder pack fails
                else: 
                    current_user.is_founder = False 
                    # Get subscription code from plan_object or subscription part of verification data
                    current_user.paystack_subscription_code = payment_data.get("plan_object", {}).get("subscriptions", [{}])[0].get("subscription_code") or \
                                                               payment_data.get("subscription", {}).get("subscription_code", current_user.paystack_subscription_code)
                    current_user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30) 
                
                db.session.commit()
                flash(f"Your {tier_info['name']} access has been activated!", "success")
            else: flash("Subscription plan details unclear. Contact support.", "warning")
            return redirect(url_for('account'))
        else:
            flash(f"Paystack payment not successful: {verification_data.get('data', {}).get('gateway_response', 'Unknown reason')}", "danger")
            return redirect(url_for('account'))
    except requests.exceptions.HTTPError as e:
        flash(f"Error verifying payment with Paystack: {e.response.status_code}. Please contact support if payment was made.", "danger")
        print(f"Paystack Verification HTTP Error: {e} - Response: {e.response.text if e.response else 'No response'}")
        return redirect(url_for('account'))
    except Exception as e:
        flash(f"Payment verification error. Contact support.", "danger"); print(f"Paystack Callback Error: {e}")
        return redirect(url_for('account'))

# --- Paystack Webhook Handler (Enhanced) ---
@app.route('/paystack_webhook', methods=['POST'])
def paystack_webhook():
    paystack_secret = app.config['PAYSTACK_SECRET_KEY']
    signature = request.headers.get('X-Paystack-Signature')
    payload_body = request.data 

    if not signature or not paystack_secret:
        print("Webhook Error: Missing signature or Paystack secret key."); abort(400) 
    hash_obj = hmac.new(paystack_secret.encode('utf-8'), payload_body, hashlib.sha512)
    expected_signature = hash_obj.hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        print("Webhook Error: Invalid signature."); abort(400) 
    
    event_data_full = request.get_json(); event_type = event_data_full.get('event')
    data = event_data_full.get('data', {})
    print(f"Webhook received and verified: {event_type}"); print(f"Webhook data: {json.dumps(data, indent=2)}")

    user = None; customer_data = data.get('customer', {})
    if customer_data:
        customer_email = customer_data.get('email'); customer_code = customer_data.get('customer_code')
        if customer_email: user = User.query.filter_by(email=customer_email).first()
        if not user and customer_code: user = User.query.filter_by(paystack_customer_code=customer_code).first()
    
    if not user:
        sub_code_event = data.get('subscription_code') or \
                         (isinstance(data.get('subscription'), dict) and data['subscription'].get('subscription_code')) or \
                         (isinstance(data.get('plan_object'), dict) and isinstance(data['plan_object'].get('subscriptions'), list) and data['plan_object']['subscriptions'] and data['plan_object']['subscriptions'][0].get('subscription_code'))
        if sub_code_event: user = User.query.filter_by(paystack_subscription_code=sub_code_event).first()
        if not user:
             print(f"Webhook: User not found. Cust Data: {customer_data}, Sub Code: {sub_code_event}")
             return jsonify({"status": "success", "message": "User not found or event not relevant"}), 200

    if user:
        print(f"Webhook: Processing event for user {user.email}")
        if event_type == 'charge.success':
            # For subscription renewals. Initial charge success is handled by callback.
            # A charge.success may also relate to a subscription if it contains plan/subscription info.
            plan_data = data.get('plan', {}) # For one-time charges tied to plans
            subscription_data_from_charge = data.get('subscription', {}) # For charge events tied to subscriptions API

            if user.paystack_subscription_code and \
               (user.paystack_subscription_code == subscription_data_from_charge.get('subscription_code') or \
                PAYSTACK_PLAN_CODES.get(user.subscription_tier) == plan_data.get('plan_code') ):
                print(f"Processing RENEWAL via charge.success for user: {user.email}, tier: {user.subscription_tier}")
                user.monthly_generations_used = 0; user.subscription_status = 'active' 
                paid_at_str = data.get('paid_at')
                next_payment_date_str = subscription_data_from_charge.get('next_payment_date') # Ideal for next period end
                
                if next_payment_date_str:
                    try: user.current_period_end = isoparse(next_payment_date_str)
                    except: user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
                elif paid_at_str: # If next_payment_date not available, calculate from paid_at
                    try: user.current_period_end = isoparse(paid_at_str) + datetime.timedelta(days=30)
                    except: user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
                else: # Fallback
                    user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
                db.session.commit(); print(f"Subscription for {user.email} renewed. Next period ends: {user.current_period_end}")
            else: print(f"Charge.success for user {user.email} not clearly a renewal for current app sub. No action.")

        elif event_type == 'subscription.create':
            sub_code = data.get('subscription_code'); plan_code = data.get('plan', {}).get('plan_code')
            customer_code = data.get('customer', {}).get('customer_code'); next_payment_date_str = data.get('next_payment_date')
            if user.paystack_customer_code != customer_code: user.paystack_customer_code = customer_code
            user.paystack_subscription_code = sub_code
            matched_tier = None
            for tier_key, pc_val in PAYSTACK_PLAN_CODES.items():
                if pc_val == plan_code: matched_tier = tier_key; break
            if matched_tier and matched_tier in TIER_DETAILS:
                tier_info = TIER_DETAILS[matched_tier]
                user.subscription_tier = matched_tier; user.monthly_generations_allowed = tier_info["generations"]
                user.subscription_status = 'active'; user.monthly_generations_used = 0
                if next_payment_date_str:
                    try: user.current_period_end = isoparse(next_payment_date_str)
                    except: user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
                elif matched_tier == 'founder': user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=TIER_DETAILS["founder"]["duration_days"])
                else: user.current_period_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
                if matched_tier == 'founder': user.is_founder = True
                db.session.commit(); print(f"Sub details synced via subscription.create for {user.email}, sub: {sub_code}, tier: {matched_tier}")
            else: print(f"Webhook: Plan code {plan_code} from sub.create not recognized for {user.email}")

        elif event_type in ['subscription.disable', 'subscription.cancel', 'subscription.not_renew']:
            event_sub_code = data.get('subscription_code')
            if user.paystack_subscription_code == event_sub_code:
                print(f"Processing {event_type} for user {user.email}")
                user.subscription_status = 'inactive'; user.is_founder = False # If founder pack cancelled, they are no longer founder
                # Consider reverting tier to 'free' and limits
                # user.subscription_tier = 'free'
                # user.monthly_generations_allowed = 10 
                db.session.commit(); print(f"Subscription status inactive for {user.email} due to {event_type}.")
            else: print(f"Webhook {event_type}: sub_code mismatch for {user.email}. No action.")
        
        elif event_type == 'invoice.payment_failed':
            event_sub_code = data.get('subscription', {}).get('subscription_code')
            if user.paystack_subscription_code == event_sub_code:
                print(f"Processing {event_type} for user {user.email}")
                user.subscription_status = 'past_due' 
                db.session.commit(); print(f"Subscription status past_due for {user.email} due to {event_type}.")
            else: print(f"Webhook {event_type}: sub_code mismatch for {user.email}. No action.")
    return jsonify({"status": "success"}), 200

# --- Content Generation Routes ---
@app.route('/generate_local_biz_captions', methods=['POST'])
@login_required 
def generate_local_biz_captions():
    # ... (Full usage tracking logic from _v2_09_founder_pack, including founder expiry check) ...
    if current_user.is_founder and current_user.current_period_end and datetime.datetime.now(datetime.UTC) > current_user.current_period_end:
        flash("Your Founder's Pack access has expired. Please subscribe to a plan to continue.", "info")
        current_user.subscription_tier = 'free'; current_user.is_founder = False
        current_user.monthly_generations_allowed = 10; current_user.free_generations_used = 0; current_user.monthly_generations_used = 0
        db.session.commit(); return jsonify({"error": "Founder's Pack expired. Please subscribe."}), 403
    if current_user.subscription_status != 'active': return jsonify({"error": "Subscription not active. Please check your account or subscribe."}), 403
    allowed_generations = current_user.monthly_generations_allowed; used_generations_field = 'monthly_generations_used'; limit_type = "monthly"
    if current_user.subscription_tier == 'free': used_generations_field = 'free_generations_used'; limit_type = "free"
    if getattr(current_user, used_generations_field) >= allowed_generations:
        return jsonify({"error": f"Your {limit_type} generation limit ({allowed_generations}) reached. Please upgrade or wait for reset."}), 403
    if not gemini_model: return jsonify({"error": "Gemini API model not configured."}), 500
    try:
        data = request.get_json(); prompt = construct_local_biz_caption_prompt(data)
        print("---- Constructed Local Biz Prompt ----\n", prompt, "\n------------------------------------")
        response = gemini_model.generate_content(prompt); generated_text = ""
        if response.candidates and response.candidates[0].content.parts: generated_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text') and response.text: generated_text = response.text
        print("---- Gemini API Response Text (Local Biz) ----\n", generated_text, "\n--------------------------------------------")
        num_variations_requested = int(data.get('numVariations', 3))
        final_content = parse_ai_response_into_blocks(generated_text, num_variations_requested)
        print("---- Parsed Content Blocks (Local Biz) ----\n", final_content, "\n-------------------------------------")
        if not final_content:
            error_message = "AI could not generate content."; 
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback: 
                for rating in response.prompt_feedback.safety_ratings:
                    if rating.category.name != "HARM_CATEGORY_UNSPECIFIED" and rating.probability.name not in ["NEGLIGIBLE", "LOW"]:
                        error_message = f"Content generation blocked: ({rating.category.name}). Revise input."; break
            return jsonify({"error": error_message}), 400
        setattr(current_user, used_generations_field, getattr(current_user, used_generations_field) + 1)
        db.session.commit(); return jsonify({"captions": final_content})
    except Exception as e: print(f"Error: {e}"); return jsonify({"error": f"Internal error: {str(e)}"}), 500

@app.route('/generate_artisan_description', methods=['POST'])
@login_required 
def generate_artisan_description():
    # ... (Full usage tracking logic from _v2_09_founder_pack, including founder expiry check) ...
    if current_user.is_founder and current_user.current_period_end and datetime.datetime.now(datetime.UTC) > current_user.current_period_end:
        flash("Your Founder's Pack access has expired. Please subscribe to a plan to continue.", "info")
        current_user.subscription_tier = 'free'; current_user.is_founder = False
        current_user.monthly_generations_allowed = 10; current_user.free_generations_used = 0; current_user.monthly_generations_used = 0
        db.session.commit(); return jsonify({"error": "Founder's Pack expired. Please subscribe."}), 403
    if current_user.subscription_status != 'active': return jsonify({"error": "Subscription not active. Please check your account or subscribe."}), 403
    if current_user.subscription_tier == 'standard': return jsonify({"error": "Artisan tool requires Premium or Founder's plan. Please upgrade."}), 403
    allowed_generations = current_user.monthly_generations_allowed; used_generations_field = 'monthly_generations_used'; limit_type = "monthly"
    if current_user.subscription_tier == 'free': used_generations_field = 'free_generations_used'; limit_type = "free"
    if getattr(current_user, used_generations_field) >= allowed_generations:
         return jsonify({"error": f"Your {limit_type} generation limit ({allowed_generations}) reached. Please upgrade or wait for reset."}), 403
    if not gemini_model: return jsonify({"error": "Gemini API model not configured."}), 500
    try:
        data = request.get_json(); prompt = construct_artisan_description_prompt(data)
        print("---- Constructed Artisan Prompt ----\n", prompt, "\n----------------------------------")
        response = gemini_model.generate_content(prompt); generated_text = ""
        if response.candidates and response.candidates[0].content.parts: generated_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text') and response.text: generated_text = response.text
        print("---- Gemini API Response Text (Artisan) ----\n", generated_text, "\n--------------------------------------------")
        num_variations_requested = int(data.get('numVariations', 2))
        final_content = parse_ai_response_into_blocks(generated_text, num_variations_requested)
        print("---- Parsed Content Blocks (Artisan) ----\n", final_content, "\n---------------------------------------")
        if not final_content:
            error_message = "AI could not generate content."; 
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback: 
                 for rating in response.prompt_feedback.safety_ratings:
                    if rating.category.name != "HARM_CATEGORY_UNSPECIFIED" and rating.probability.name not in ["NEGLIGIBLE", "LOW"]:
                        error_message = f"Content generation blocked: ({rating.category.name}). Revise input."; break
            return jsonify({"error": error_message}), 400
        setattr(current_user, used_generations_field, getattr(current_user, used_generations_field) + 1)
        db.session.commit(); return jsonify({"descriptions": final_content})
    except Exception as e: print(f"Error: {e}"); return jsonify({"error": f"Internal error: {str(e)}"}), 500

if __name__ == '__main__':
    with app.app_context():
        try:
            # Attempt to initialize FOUNDER_PACKS_CLAIMED from DB
            # This requires the User table to exist.
            if db.engine.dialect.has_table(db.engine.connect(), User.__tablename__):
                 FOUNDER_PACKS_CLAIMED = User.query.filter_by(is_founder=True).count()
                 print(f"Initialized Founder Packs Claimed from DB: {FOUNDER_PACKS_CLAIMED}")
            else:
                 print("User table not found on startup (migrations might be pending). FOUNDER_PACKS_CLAIMED set to 0.")
                 FOUNDER_PACKS_CLAIMED = 0
        except Exception as e_init:
            print(f"Error initializing founder pack count from DB (migrations might be pending or DB not ready): {e_init}")
            FOUNDER_PACKS_CLAIMED = 0 
            
    app.run(debug=True, port=5000)