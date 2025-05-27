import os
import json
import re 
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()
app = Flask(__name__)

try:
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise ValueError("GEMINI_API_KEY not found in .env file or environment variables.")
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
except Exception as e:
    print(f"Error configuring Gemini API: {e}")
    model = None

# --- Prompt construction functions (construct_local_biz_caption_prompt and construct_artisan_description_prompt) ---
# These remain the same as in content_engine_flask_app_08.
# The AI is still instructed to provide a Visual Suggestion on a new line
# and separate full variations with triple newlines.
# For brevity, I am not repeating them here, but assume they are the same as the previous version.
# Ensure your local app.py has these functions as they were in content_engine_flask_app_08.

def construct_local_biz_caption_prompt(data):
    business_name = data.get('businessName') or "Our business"
    business_type = data.get('businessType', 'local business')
    post_type = data.get('postType', 'general announcement').replace('_', ' ')
    key_message = data.get('keyMessage', 'something exciting!')
    target_audience = data.get('targetAudience')
    tone = data.get('tone', 'friendly & casual').replace('_', ' ')
    call_to_action = data.get('callToAction', 'no specific cta')
    include_emojis = data.get('includeEmojis') == 'on'
    num_variations = int(data.get('numVariations', 3))

    prompt_lines = [
        f"You are an expert social media manager specializing in engaging content for diverse local businesses.",
        f"Generate {num_variations} distinct social media caption variations.",
        f"The business type is: '{business_type}'.",
        f"The desired tone for the caption(s) is '{tone}'.",
        f"The purpose of the post is: '{post_type}'.",
        f"Key message/details to include: '{key_message}'.",
    ]
    if business_name != "Our business":
        prompt_lines.append(f"The business name is '{business_name}'.")
    if target_audience:
        prompt_lines.append(f"The primary target audience for this post is: '{target_audience}'. Tailor the language and appeal accordingly.")
    if call_to_action != "no specific cta" and call_to_action != "custom_cta":
        cta_text_map = {"visit_us": "Visit Us Today!", "shop_now_online": "Shop Now/Order Online!", "book_appointment_now": "Book Your Appointment Now!", "learn_more": "Learn More (link in bio/DM us)!", "tag_friend": "Tag a Friend Who Needs This!", "contact_us": "Contact Us for Details!"}
        cta_text = cta_text_map.get(call_to_action, call_to_action.replace('_', ' ').title() + "!")
        prompt_lines.append(f"Include a call to action like: '{cta_text}'.")
    elif call_to_action == "custom_cta":
        prompt_lines.append("The user wants a custom call to action, infer it from the key message or make a general one if not clear.")
    if include_emojis: prompt_lines.append("Please include relevant emojis.")
    else: prompt_lines.append("Do not use any emojis.")
    prompt_lines.extend([
        "Instructions for the AI:",
        f"- Tailor each caption variation specifically to the nature of a '{business_type}' and its target audience if specified.",
        "- Each caption variation should be a complete thought.",
        "- After each complete caption variation, on a new line, add a brief suggestion for a suitable visual starting exactly with 'Visual Suggestion:'.",
        "- Ensure each complete variation (main caption text followed by its single 'Visual Suggestion:' line) is clearly separated from the next complete variation by a TRIPLE newline (two blank lines).",
        "- Focus solely on generating the caption text and the visual suggestion. Do not add any other introductory or concluding remarks, or labels like 'Caption 1:'."
    ])
    return "\n".join(prompt_lines)

def construct_artisan_description_prompt(data):
    creator_name = data.get('creatorName')
    product_name = data.get('productName', 'this unique item')
    product_category = data.get('productCategory', 'handmade product')
    key_materials = data.get('keyMaterials', 'quality materials')
    creation_process = data.get('creationProcess')
    inspiration = data.get('inspiration')
    unique_selling_points = data.get('uniqueSellingPoints', 'it is special')
    target_audience = data.get('targetAudience')
    artisan_tone = data.get('artisanTone', 'story_driven_evocative').replace('_', ' ')
    num_variations = int(data.get('numVariations', 2))
    prompt_lines = [
        f"You are an expert copywriter specializing in crafting compelling and unique product descriptions for artisans and handmade sellers.",
        f"Generate {num_variations} distinct product description variations.",
        f"The product is: '{product_name}', a type of '{product_category}'.",
        f"It is made primarily from: '{key_materials}'.",
        f"The desired tone for the description(s) is '{artisan_tone}'.",
        f"Key unique selling points and customer benefits are: '{unique_selling_points}'.",
    ]
    if creator_name: prompt_lines.append(f"The creator/brand name is '{creator_name}'.")
    if creation_process: prompt_lines.append(f"Highlights of the creation process/technique: '{creation_process}'.")
    if inspiration: prompt_lines.append(f"The inspiration or story behind the product is: '{inspiration}'.")
    if target_audience: prompt_lines.append(f"The primary target audience for this product is: '{target_audience}'. Emphasize aspects that would appeal to them.")
    prompt_lines.extend([
        "Instructions for the AI:",
        f"- Write each description variation to be evocative and highlight the uniqueness of a handmade '{product_category}', keeping the target audience in mind if specified.",
        "- Each description should be well-structured (e.g., 1-2 paragraphs).",
        "- After each complete product description variation, on a new line, add a brief suggestion for a suitable primary product image starting exactly with 'Visual Suggestion:'.",
        "- Ensure each complete variation (description + its single 'Visual Suggestion:' line) is clearly separated from the next complete variation by a TRIPLE newline (two blank lines).",
        "- Focus solely on generating the product description text and the visual suggestion. Do not add any other introductory or concluding remarks, or labels like 'Description 1:'."
    ])
    return "\n".join(prompt_lines)

# --- NEW/IMPROVED Parsing Function ---
def parse_ai_response_into_blocks(generated_text, num_variations_requested):
    """
    Parses the AI's generated text into the requested number of blocks.
    Each block should contain a main content piece and its visual suggestion.
    This version iterates through lines to group them more robustly.
    """
    if not generated_text:
        return []

    lines = [line.strip() for line in generated_text.splitlines()] # Use splitlines() for universal newlines
    
    all_variations = []
    current_variation_lines = []
    for line in lines:
        if not line: # Skip empty lines that might be used as separators
            # If we have content in current_variation_lines AND it doesn't have a VS yet,
            # AND a blank line appears, it *might* be a separator.
            # However, our main logic relies on finding "Visual Suggestion:" to complete a block.
            # If the AI uses blank lines to separate and current_variation_lines has text,
            # it implies the AI might not have added a VS for the previous block.
            # This is tricky. Let's assume "Visual Suggestion:" is the primary delimiter for now.
            continue 

        current_variation_lines.append(line)
        if line.startswith("Visual Suggestion:"):
            # This line is a visual suggestion, it completes the current variation block
            if current_variation_lines: # Should always be true if VS is found
                all_variations.append("\n".join(current_variation_lines))
                current_variation_lines = [] # Reset for the next variation
                if len(all_variations) == num_variations_requested:
                    break 
        # If it's not a "Visual Suggestion:" line, it's part of the main content of the current variation.
        # We just keep appending to current_variation_lines.
        # The block completes when its "Visual Suggestion:" line is found and processed.
    
    # In case the last variation didn't have a Visual Suggestion or the loop ended
    # before processing a final Visual Suggestion line that was collected.
    if current_variation_lines and len(all_variations) < num_variations_requested:
        all_variations.append("\n".join(current_variation_lines))

    # Ensure we only return up to the requested number, even if parsing found more (unlikely with current logic)
    if len(all_variations) > num_variations_requested:
        return all_variations[:num_variations_requested]
        
    return all_variations


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_local_biz_captions', methods=['POST'])
def generate_local_biz_captions():
    if not model: return jsonify({"error": "Gemini API model not configured."}), 500
    try:
        data = request.get_json()
        if not data: return jsonify({"error": "No data provided."}), 400
        
        prompt = construct_local_biz_caption_prompt(data)
        print("---- Constructed Local Biz Prompt ----\n", prompt, "\n------------------------------------")
        
        response = model.generate_content(prompt)
        generated_text = ""
        if response.candidates and response.candidates[0].content.parts:
            generated_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text') and response.text: 
            generated_text = response.text
        
        print("---- Gemini API Response Text (Local Biz) ----\n", generated_text, "\n--------------------------------------------")
        
        num_variations_requested = int(data.get('numVariations', 3))
        final_content = parse_ai_response_into_blocks(generated_text, num_variations_requested)
        
        print("---- Parsed Content Blocks (Local Biz) ----\n", final_content, "\n-------------------------------------")

        if not final_content:
            error_message = "The AI could not generate captions. Please try rephrasing."
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback: 
                for rating in response.prompt_feedback.safety_ratings:
                    if rating.category.name != "HARM_CATEGORY_UNSPECIFIED" and rating.probability.name not in ["NEGLIGIBLE", "LOW"]:
                        error_message = f"Content generation blocked: ({rating.category.name}). Revise input."
                        break
            return jsonify({"error": error_message}), 400
        
        return jsonify({"captions": final_content})
    except Exception as e:
        print(f"Error during local biz caption generation: {e}")
        return jsonify({"error": f"An internal error occurred: {str(e)}"}), 500

@app.route('/generate_artisan_description', methods=['POST'])
def generate_artisan_description():
    if not model: return jsonify({"error": "Gemini API model not configured."}), 500
    try:
        data = request.get_json()
        if not data: return jsonify({"error": "No data provided."}), 400
        
        prompt = construct_artisan_description_prompt(data)
        print("---- Constructed Artisan Prompt ----\n", prompt, "\n----------------------------------")

        response = model.generate_content(prompt)
        generated_text = ""
        if response.candidates and response.candidates[0].content.parts:
            generated_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text') and response.text:
            generated_text = response.text

        print("---- Gemini API Response Text (Artisan) ----\n", generated_text, "\n--------------------------------------------")

        num_variations_requested = int(data.get('numVariations', 2))
        final_content = parse_ai_response_into_blocks(generated_text, num_variations_requested)

        print("---- Parsed Content Blocks (Artisan) ----\n", final_content, "\n---------------------------------------")
        
        if not final_content:
            error_message = "The AI could not generate descriptions. Please try rephrasing."
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback: 
                 for rating in response.prompt_feedback.safety_ratings:
                    if rating.category.name != "HARM_CATEGORY_UNSPECIFIED" and rating.probability.name not in ["NEGLIGIBLE", "LOW"]:
                        error_message = f"Content generation blocked: ({rating.category.name}). Revise input."
                        break
            return jsonify({"error": error_message}), 400
        
        return jsonify({"descriptions": final_content})
    except Exception as e:
        print(f"Error during artisan description generation: {e}")
        return jsonify({"error": f"An internal error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)

