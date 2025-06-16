from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask import send_from_directory
from flask_socketio import SocketIO, emit
from datetime import datetime
import time
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import base64
import mimetypes
import mimetypes
import uuid
from sqlalchemy import create_engine, text
from flask_session import Session

app=Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')
app.config['SESSION_TYPE']='filesystem'
Session(app)

socketio = SocketIO(
    app,
    manage_session=True,
    cors_allowed_origins="*",
    cors_credentials=True,
    logger=True,
    engineio_logger=True
)

if 'RENDER' in os.environ:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE='None'
    )
else:
    app.config.update(
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_SAMESITE='Lax'
    )

users = {}
UPLOAD_FOLDER =os.environ.get('UPLOAD_FOLDER', 'uploads') 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

engine = None

def init_db():
    global engine
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    
    engine = create_engine(db_url)
    
    # Create tables if they don't exist
    with engine.connect() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL, 
            password TEXT NOT NULL
        )
        """))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS messages(
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp REAL NOT NULL,
            message_type TEXT NOT NULL DEFAULT 'text'
        )
        """))
        conn.commit()

init_db()

@socketio.on_error_default
def default_error_handler(e):
    app.logger.error(f"SocketIO error: {str(e)}")
    emit('error', {'message': 'A server error occurred'})

@app.route('/')
def index():
	return redirect(url_for('home'))
	
@app.route('/home')
def home():
	if 'user' in session:
		return redirect(url_for('chat'))
	else:
		return render_template('home.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
	response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
	#Add Mime type detection
	mime_type, _ = mimetypes.guess_type(filename)
	if mime_type:
		response.headers.set('Content-Type', mime_type)
	return response

# Add this to chat.py to handle database errors
@socketio.on_error_default
def default_error_handler(e):
    print(f"SocketIO error: {str(e)}")
    emit('error', {'message': 'A server error occurred'})
    
@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        username = session['user']
        users[request.sid] = username
        print(f'User connected: {username}')
        
        # Load messages
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT id, username, message, timestamp, message_type 
                FROM messages ORDER BY timestamp
            """))
            messages = result.fetchall()
        
        for msg in messages:
            emit('new_message', {
                'id': msg[0],
                'username': msg[1],
                'content': msg[2],
                'timestamp': msg[3],
                'type': msg[4]
            }, room=request.sid)
        
        emit('user_joined', {'username': username}, broadcast=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        try:
            with engine.connect() as conn:
                   conn.execute(text("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)"),
                   {'username': username, 'email': email, 'password': password})
                   conn.commit()
            flash('Registered successfully, please login')
            return redirect(url_for('login'))

        except IntegrityError:
            flash('Username or email already exists')
            return redirect(url_for('register'))
        
        except SQLAlchemyError as e:
            flash(f'Registration failed: {str(e)}')
            return redirect(url_for('register'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method =="POST":
		username = request.form['username']
		password = request.form['password']
		
		with engine.connect() as conn:
		              result = conn.execute(text("""SELECT password FROM users WHERE username = :username"""),{'username': username})
		              user = result.fetchone()
		              
		if user and check_password_hash(user[0], password):
		      session['user'] = username
		      return redirect(url_for('chat'))
		else:
		      flash('Invalid credentials')
		      return redirect(url_for('login'))
		
	return render_template('login.html')

@app.route('/chat')
def chat():
	if 'user' in session:
	    return render_template('chat.html', username=session['user'])
	else:
		return redirect(url_for('login'))
		
@socketio.on('disconnect')
def handle_disconnect(reason):
		if request.sid in users:
			username = users[request.sid]
			del users[request.sid]
			emit('user_left', {'username': username, 'timestamp': time.time()}, broadcast=True)
			print(f'Client disconnected: {request.sid}')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp3', 'mp4'}
def allowed_file(mime_type):
	allowed ={'image/png', 'image/jpeg', 'image/gif', 'application/pdf', 'audio/mpeg', 'video/mp4'}
	return mime_type in allowed

@socketio.on('send_message')
def handle_message(data):
    if 'user' not in session:
        print("Error: User not authenticated")
        return
    username = session['user']
    if not username:
        return  # Ignore unauthenticated

    saved_file_path = None
    try:
        message_content = data['content']
        message_type = data.get('type', 'text')
        timestamp = time.time()
        message_id = None
        
        print(f"Received message type: {message_type}")
        print(f"Content length: {len(message_content)}")
        if message_type != 'text':
            file_path = None
            try:
                # Process data URL
                header, encoded_content = data['content'].split(',', 1)
                content = base64.b64decode(encoded_content)
                
                decoded_size = (len(encoded_content) * 3) // 4
                if decoded_size > 30 * 1024 * 1024: 
                    emit('error', {'message': 'File too large (max 30MB)'}, room=request.sid)
                    return
                
                mime_type = header.split(';')[0].split(':')[1]
                if not allowed_file(mime_type):
                    emit('error', {'message': 'File type not allowed'}, room=request.sid)
                    return
                
                ext = mimetypes.guess_extension(mime_type) or '.bin'
                filename = secure_filename(f"{uuid.uuid4()}{ext}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                with open(file_path, 'wb') as f:
                    f.write(content)
                print(f"File saved to: {file_path}")
                message_content = f"/uploads/{filename}"; 
                
                if message_type == 'pdf':
                	original_filename = secure_filename(file.filename) if hasattr(file, 'filename') else "document.pdf"
                	message_content = f"/uploads/{filename}?name={original_filename}"
                else:
                	message_content = f"/uploads/{filename}"
                saved_file_path = file_path
                
            except Exception as e:
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
                print(f"File processing failed: {str(e)}")
                emit('error', {'message': 'File upload failed'}, room=request.sid)
                return

        with engine.connect() as conn:
            result = conn.execute(text("""
                INSERT INTO messages (username, message, timestamp, message_type)
                VALUES (:username, :message, :timestamp, :message_type)
                RETURNING id
            """), {
                'username': username,
                'message': message_content,
                'timestamp': timestamp,
                'message_type': message_type
            })
            message_id = result.scalar()
            conn.commit()
        
        saved_file_path = None
        
        if message_id:
            try:
                emit('new_message', {
                    'id': message_id,
                    'username': username,
                    'content': message_content,
                    'type': message_type,
                    'timestamp': timestamp
                }, broadcast=True)
            except Exception as e:
                print(f"Broadcast error: {str(e)}")
    
    except Exception as e:
        if saved_file_path and os.path.exists(saved_file_path):
            try:
                os.remove(saved_file_path)
            except Exception:
                pass
        print(f"Critical error in send_message: {str(e)}")
        emit('error', {'message': 'Failed to send message due to server error'}, room=request.sid)

@socketio.on('delete_message')
def handle_delete(message_id):
    if 'user' not in session:
    	return
    username = session['user']
    
    try:
    	with engine.connect() as conn:
    	       result = conn.execute(text("""SELECT username, message, message_type
    	       FROM messages
    	       WHERE id = :id"""), {'id': message_id})
    	       row = result.fetchone()
    	       
    	       if not row:
    	       	return
    	       message_username, message_content, message_type = row
    	       
    	       if message_username != username:
    	       	return
    	       	
    	       conn.execute(text("""DELETE FROM messages WHERE id = :id"""), {'id': message_id})
    	       conn.commit()
    	       
    	       if message_type != 'text':
    	           file_path = message_content.replace('/uploads/', '')
    	           full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_path)
    	           if os.path.exists(full_path):
    	                   try:
    	                   	os.remove(full_path)
    	                   except Exception as e:
    	                   	print(f"Error deleting file: {str(e)}")
    	emit('message_deleted', message_id, broadcast=True)
    except Exception as e:
    	print(f"Delete error: {str(e)}")

def cleanup_uploads():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        return
        
    now = time.time()
    for f in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f)
        try:
            if os.path.isfile(filepath) and os.stat(filepath).st_mtime < now - 3600 * 24:
                os.remove(filepath)
        except Exception as e:
            print(f"Error deleting {filepath}: {str(e)}")
	
@app.route('/logout',  methods=['GET', 'POST'])
def logout():
	session.pop('user', None)
	flash('Logged out successfully.')
	return redirect(url_for('login'))
	
if (__name__) =='__main__':
	port = int(os.environ.get('PORT', 9000))
	os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
	socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug =True)