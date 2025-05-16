from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, send, emit
import os
import json
from datetime import datetime, timedelta
import hashlib
import ipaddress

app = Flask(__name__)
app.config['SECRET_KEY'] = 'miyao'  #记得修改成使用强密钥
socketio = SocketIO(app)

# 存储聊天记录的文件
CHAT_FILE = 'chat_history.json'
# 存储管理员信息的文件
ADMINS_FILE = 'admins.json'
# 存储封禁信息的文件
BANS_FILE = 'bans.json'
# 存储禁言信息的文件
MUTES_FILE = 'mutes.json'

# 确保数据文件存在
def ensure_file_exists(file_path, default_content=[]):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump(default_content, f)

ensure_file_exists(CHAT_FILE)
ensure_file_exists(ADMINS_FILE)
ensure_file_exists(BANS_FILE)
ensure_file_exists(MUTES_FILE)

# 读取数据文件
def load_data(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []

# 保存数据文件
def save_data(file_path, data):
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving {file_path}: {e}")

# 管理员认证相关
def hash_password(password):
    """对密码进行哈希处理"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def create_admin(username, password):
    """创建新管理员"""
    admins = load_data(ADMINS_FILE)
    if any(admin['username'] == username for admin in admins):
        return False
    
    hashed_password = hash_password(password)
    new_admin = {
        'username': username,
        'password': hashed_password,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    admins.append(new_admin)
    save_data(ADMINS_FILE, admins)
    return True

def authenticate_admin(username, password):
    """验证管理员身份"""
    admins = load_data(ADMINS_FILE)
    for admin in admins:
        if admin['username'] == username and admin['password'] == hash_password(password):
            return True
    return False

def change_admin_password(username, old_password, new_password):
    """修改管理员密码"""
    admins = load_data(ADMINS_FILE)
    for i, admin in enumerate(admins):
        if admin['username'] == username:
            # 验证旧密码
            if admin['password'] != hash_password(old_password):
                return False
            
            # 更新密码
            admins[i]['password'] = hash_password(new_password)
            save_data(ADMINS_FILE, admins)
            return True
    
    return False

# 封禁相关功能
def ban_ip(ip, reason, admin_username):
    """封禁IP"""
    bans = load_data(BANS_FILE)
    # 检查是否已被封禁
    for ban in bans:
        if ban['ip'] == ip:
            return False, "该IP已被封禁"
    
    bans.append({
        'ip': ip,
        'reason': reason,
        'admin': admin_username,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    save_data(BANS_FILE, bans)
    return True, "IP已成功封禁"

def is_ip_banned(ip):
    """检查IP是否被封禁"""
    bans = load_data(BANS_FILE)
    return any(ban['ip'] == ip for ban in bans)

def get_ban_info(ip):
    """获取IP封禁信息"""
    bans = load_data(BANS_FILE)
    for ban in bans:
        if ban['ip'] == ip:
            return ban
    return None

def unban_ip(ip):
    """解除IP封禁"""
    bans = load_data(BANS_FILE)
    updated_bans = [ban for ban in bans if ban['ip'] != ip]
    if len(updated_bans) < len(bans):
        save_data(BANS_FILE, updated_bans)
        return True, "IP封禁已解除"
    return False, "该IP未被封禁"

# 禁言相关功能
def mute_user(target, minutes, reason, admin_username):
    """禁言用户（IP或用户名）"""
    mutes = load_data(MUTES_FILE)
    expires_at = (datetime.now() + timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S')
    
    # 检查是否已经被禁言
    for i, mute in enumerate(mutes):
        if mute['target'] == target:
            # 更新现有禁言
            mutes[i] = {
                'target': target,
                'expires_at': expires_at,
                'reason': reason,
                'admin': admin_username
            }
            save_data(MUTES_FILE, mutes)
            return True, "禁言已更新"
    
    # 添加新禁言
    mutes.append({
        'target': target,
        'expires_at': expires_at,
        'reason': reason,
        'admin': admin_username
    })
    save_data(MUTES_FILE, mutes)
    return True, "用户已被禁言"

def is_user_muted(target):
    """检查用户是否被禁言"""
    mutes = load_data(MUTES_FILE)
    now = datetime.now()
    
    for mute in mutes:
        if mute['target'] == target:
            expires_at = datetime.strptime(mute['expires_at'], '%Y-%m-%d %H:%M:%S')
            if now < expires_at:
                return {
                    'is_muted': True,
                    'expires_at': mute['expires_at'],
                    'reason': mute['reason'],
                    'admin': mute['admin']
                }
            else:
                # 禁言已过期，清理
                unmute_user(target)
    
    return {'is_muted': False}

def unmute_user(target):
    """解除用户禁言"""
    mutes = load_data(MUTES_FILE)
    updated_mutes = [mute for mute in mutes if mute['target'] != target]
    if len(updated_mutes) < len(mutes):
        save_data(MUTES_FILE, updated_mutes)
        return True, "禁言已解除"
    return False, "该用户未被禁言"

# 检查IP是否有效
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# 检查用户是否可以发送消息
def can_user_send_message(username, client_ip):
    # 检查IP封禁
    if is_ip_banned(client_ip):
        ban_info = get_ban_info(client_ip)
        return False, f"您的IP已被封禁，原因: {ban_info['reason']}"
    
    # 检查用户名禁言
    mute_info = is_user_muted(username)
    if mute_info['is_muted']:
        expires_at = datetime.strptime(mute_info['expires_at'], '%Y-%m-%d %H:%M:%S')
        remaining_minutes = int((expires_at - datetime.now()).total_seconds() // 60)
        return False, f"您已被禁言，剩余时间: {remaining_minutes} 分钟，原因: {mute_info['reason']}"
    
    # 检查IP禁言
    mute_info = is_user_muted(client_ip)
    if mute_info['is_muted']:
        expires_at = datetime.strptime(mute_info['expires_at'], '%Y-%m-%d %H:%M:%S')
        remaining_minutes = int((expires_at - datetime.now()).total_seconds() // 60)
        return False, f"您的IP已被禁言，剩余时间: {remaining_minutes} 分钟，原因: {mute_info['reason']}"
    
    return True, ""

# 存储当前用户信息
users = {}

# 路由
@app.route('/')
def index():
    if 'admin' in session:
        return redirect(url_for('admin_dashboard'))
    
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if authenticate_admin(username, password):
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/admin')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    bans = load_data(BANS_FILE)
    mutes = load_data(MUTES_FILE)
    chat_history = load_data(CHAT_FILE)
    
    # 过滤掉已过期的禁言
    current_mutes = []
    now = datetime.now()
    for mute in mutes:
        expires_at = datetime.strptime(mute['expires_at'], '%Y-%m-%d %H:%M:%S')
        if now < expires_at:
            current_mutes.append({
                'target': mute['target'],
                'remaining': f"{int((expires_at - now).total_seconds() // 60)} 分钟",
                'reason': mute['reason'],
                'admin': mute['admin'],
                'expires_at': mute['expires_at']
            })
    
    return render_template('admin_dashboard.html', 
                          bans=bans, 
                          mutes=current_mutes, 
                          chat_history=chat_history,
                          admin_username=session['admin'])

@app.route('/admin/change_password', methods=['GET', 'POST'])
def admin_change_password():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            return render_template('admin_change_password.html', error='新密码和确认密码不匹配')
        
        if change_admin_password(session['admin'], old_password, new_password):
            return render_template('admin_change_password.html', success='密码已成功修改')
        else:
            return render_template('admin_change_password.html', error='旧密码不正确')
    
    return render_template('admin_change_password.html')

@app.route('/admin/ban', methods=['POST'])
def admin_ban():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': '未授权'}), 403
    
    ip = request.form.get('ip')
    reason = request.form.get('reason')
    
    if not is_valid_ip(ip):
        return jsonify({'success': False, 'message': '无效的IP地址'}), 400
    
    success, message = ban_ip(ip, reason, session['admin'])
    return jsonify({'success': success, 'message': message})

@app.route('/admin/unban', methods=['POST'])
def admin_unban():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': '未授权'}), 403
    
    ip = request.form.get('ip')
    
    if not is_valid_ip(ip):
        return jsonify({'success': False, 'message': '无效的IP地址'}), 400
    
    success, message = unban_ip(ip)
    return jsonify({'success': success, 'message': message})

@app.route('/admin/mute', methods=['POST'])
def admin_mute():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': '未授权'}), 403
    
    target = request.form.get('target')
    minutes = int(request.form.get('minutes'))
    reason = request.form.get('reason')
    
    if minutes <= 0:
        return jsonify({'success': False, 'message': '禁言时间必须大于0分钟'}), 400
    
    success, message = mute_user(target, minutes, reason, session['admin'])
    return jsonify({'success': success, 'message': message})

@app.route('/admin/unmute', methods=['POST'])
def admin_unmute():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': '未授权'}), 403
    
    target = request.form.get('target')
    
    success, message = unmute_user(target)
    return jsonify({'success': success, 'message': message})

@app.route('/admin/delete_message', methods=['POST'])
def admin_delete_message():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': '未授权'}), 403
    
    index = int(request.form.get('index'))
    chat_history = load_data(CHAT_FILE)
    
    if 0 <= index < len(chat_history):
        deleted_msg = chat_history.pop(index)
        save_data(CHAT_FILE, chat_history)
        
        # 向所有客户端发送删除消息事件
        socketio.emit('message_deleted', {'index': index})
        
        return jsonify({'success': True, 'message': '消息已删除'})
    else:
        return jsonify({'success': False, 'message': '消息索引无效'}), 400

# WebSocket事件
@socketio.on('connect')
def handle_connect():
    client_ip = request.remote_addr
    
    # 检查IP封禁
    if is_ip_banned(client_ip):
        ban_info = get_ban_info(client_ip)
        emit('banned', {'message': f'您的IP已被封禁，原因: {ban_info["reason"]}'})
        return False
    
    # 发送历史消息给新连接的用户
    history = load_data(CHAT_FILE)
    emit('history_messages', history)

@socketio.on('message')
def handle_message(data):
    username = users.get(request.sid, '匿名用户')
    message = data['message']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = request.remote_addr
    
    # 检查用户是否可以发送消息
    can_send, reason = can_user_send_message(username, client_ip)
    if not can_send:
        emit('error', {'message': reason})
        return
    
    # 构建消息对象
    msg_obj = {
        'username': username,
        'message': message,
        'timestamp': timestamp
    }
    
    # 保存到文件
    history = load_data(CHAT_FILE)
    history.append(msg_obj)
    save_data(CHAT_FILE, history)
    
    # 广播消息给所有客户端
    send(msg_obj, broadcast=True)

@socketio.on('set_username')
def handle_set_username(data):
    new_username = data['username']
    users[request.sid] = new_username
    emit('username_set', {'username': new_username})

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        del users[request.sid]

if __name__ == '__main__':
    # 确保至少有一个管理员账户
    if not load_data(ADMINS_FILE):
        print("已经正常启动")
        print("创建默认管理员账户...")
        print("用户名: admin")
        print("密码: admin123")
        print("重要：请在首次登录后修改密码！")
        create_admin('admin', 'admin123')

    app.run(host='0.0.0.0', port=8080)    
