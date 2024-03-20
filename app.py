from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_httpauth import HTTPBasicAuth
from inference_sdk import InferenceHTTPClient
from dotenv import load_dotenv
import os, uuid, scrypt

load_dotenv()

app = Flask(__name__)
Bootstrap(app)
app.secret_key = os.urandom(24)
auth = HTTPBasicAuth()

users = {
    "admin": os.getenv('ADMIN_PASSWORD_HASH', 'default_hash')
}

@auth.verify_password
def verify_password(username, password):
    stored_hash = users.get(username)
    if stored_hash is not None:
        _, salt, hash = stored_hash.split('$')
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        computed_hash = scrypt.hash(password_bytes, salt_bytes, N=32768, r=8, p=1).hex()
        if computed_hash == hash:
            return username
    return False

CLIENT = InferenceHTTPClient(
    api_url=os.getenv('INFER_API_URL', 'http://detect.roboflow.com'),
    api_key=os.getenv('INFER_API_KEY', 'lYIRJi38oj08h7LanTbL')
)

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

def handle_upload(file):
    _, file_extension = os.path.splitext(file.filename)
    unique_filename = str(uuid.uuid4()) + file_extension
    filepath = os.path.join(app.static_folder, 'uploads', unique_filename)
    file.save(filepath)
    return filepath, unique_filename

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        filepath, unique_filename = handle_upload(file)
        try:
            result = CLIENT.infer(filepath, model_id="plane-ml-classifier/2")
            highest_confidence_class = max(result['predictions'], key=lambda k: result['predictions'][k]['confidence'])
            highest_confidence_value = result['predictions'][highest_confidence_class]['confidence']
            detection_found = True
        except Exception as e:
            flash(f"An error occurred during inference: {e}")
            detection_found = False
            highest_confidence_class = None
            highest_confidence_value = 0

        image_url = url_for('static', filename=f'uploads/{unique_filename}')

        return render_template('result.html', image_url=image_url, class_name=highest_confidence_class, confidence=highest_confidence_value, detection_found=detection_found)
    return redirect(url_for('index'))

@app.route('/upload_v2', methods=['POST'])
def upload_v2():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        filepath, unique_filename = handle_upload(file)
        try:
            result = CLIENT.infer(filepath, model_id="ml-object-detection-plane-model/1")
            if result['predictions']:
                highest_confidence_prediction = max(result['predictions'], key=lambda x: x['confidence'])
                highest_confidence_class = highest_confidence_prediction['class']
                highest_confidence_value = highest_confidence_prediction['confidence']
                detection_found = True
            else:
                highest_confidence_class = None
                highest_confidence_value = 0
                detection_found = False
        except Exception as e:
            flash(f"An error occurred during inference: {e}")
            detection_found = False
            highest_confidence_class = None
            highest_confidence_value = 0

        image_url = url_for('static', filename=f'uploads/{unique_filename}')

        return render_template('result.html', image_url=image_url, class_name=highest_confidence_class, confidence=highest_confidence_value, detection_found=detection_found)
    return redirect(url_for('index'))

@app.route('/upload_v3', methods=['POST'])
def upload_v3():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        filepath, unique_filename = handle_upload(file)
        try:
            result = CLIENT.infer(filepath, model_id="ml-object-detection-plane-model/2")
            if result['predictions']:
                highest_confidence_prediction = max(result['predictions'], key=lambda x: x['confidence'])
                highest_confidence_class = highest_confidence_prediction['class']
                highest_confidence_value = highest_confidence_prediction['confidence']
                detection_found = True
            else:
                highest_confidence_class = None
                highest_confidence_value = 0
                detection_found = False
        except Exception as e:
            flash(f"An error occurred during inference: {e}")
            detection_found = False
            highest_confidence_class = None
            highest_confidence_value = 0

        image_url = url_for('static', filename=f'uploads/{unique_filename}')

        return render_template('result.html', image_url=image_url, class_name=highest_confidence_class, confidence=highest_confidence_value, detection_found=detection_found)
    return redirect(url_for('index'))

@app.route('/upload_v4', methods=['POST'])
def upload_v4():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        filepath, unique_filename = handle_upload(file)
        try:
            result = CLIENT.infer(filepath, model_id="plane-ml-classifier/1")
            highest_confidence_class = max(result['predictions'], key=lambda k: result['predictions'][k]['confidence'])
            highest_confidence_value = result['predictions'][highest_confidence_class]['confidence']
            detection_found = True
        except Exception as e:
            flash(f"An error occurred during inference: {e}")
            detection_found = False
            highest_confidence_class = None
            highest_confidence_value = 0

        image_url = url_for('static', filename=f'uploads/{unique_filename}')

        return render_template('result.html', image_url=image_url, class_name=highest_confidence_class, confidence=highest_confidence_value, detection_found=detection_found)
    return redirect(url_for('index'))

if __name__ == '__main__':
    uploads_dir = os.path.join(app.static_folder, 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
    app.run(debug=True)