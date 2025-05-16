# 乐聊 (HappyChat) | 一个基于 Flask 和 SocketIO 的在线聊天系统

乐聊 (HappyChat)是一个基于 Flask 和 SocketIO 的实时聊天应用，支持多用户在线聊天、管理员管理等功能。应用采用前后端分离设计，使用 JSON 文件存储数据，无需数据库，便于部署和使用。

## 功能特点

### 用户功能
- 匿名聊天或设置自定义用户名
- 实时接收和发送消息
- 消息历史记录永久保存
- 被封禁或禁言时的明确提示

### 管理员功能
- 安全的登录系统（支持密码修改）
- 封禁IP地址（带原因记录和封禁人信息）
- 解除IP封禁
- 对用户或IP进行临时禁言（指定分钟数）
- 解除用户禁言
- 删除特定聊天消息
- 查看所有封禁和禁言记录
- 查看完整聊天历史

## 技术栈

- 后端：Flask, Flask-SocketIO
- 前端：HTML, Tailwind CSS, JavaScript, Socket.IO
- 数据存储：JSON文件
- 安全：密码哈希存储

## 安装与运行

1. 克隆项目到本地：git clone https://github.com/yanke-studio/happychat
cd realtime-chat-app
2. 创建并激活虚拟环境：python3 -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate  # Windows
3. 安装依赖：pip install -r requirements.txt
4. 运行应用：python app.py （默认端口是5000 可以在app.py中修改。此处默认为5000演示）
5. 访问应用：
- 用户端：http://localhost:5000
- 管理端：http://localhost:5000/login

## 默认管理员账户

首次运行时，系统会自动创建一个默认管理员账户：
- 用户名：admin
- 密码：admin123

**重要提示：请在首次登录后立即修改默认密码！**

## 使用说明

### 普通用户
1. 访问主页 http://localhost:5000
2. 可以直接匿名聊天，或点击"修改昵称"设置用户名
3. 开始发送消息

### 管理员
1. 访问登录页面 http://localhost:5000/login
2. 使用管理员账户登录
3. 在控制面板中可以：
   - 封禁IP
   - 解除IP封禁
   - 禁言用户
   - 解除禁言
   - 删除消息
   - 修改管理员密码

## 文件结构
realtime-chat-app/
├── app.py                # 主应用文件
├── chat_history.json     # 聊天记录存储
├── admins.json           # 管理员账户存储
├── bans.json             # IP封禁记录存储
├── mutes.json            # 用户禁言记录存储
├── templates/            # HTML模板
│   ├── index.html        # 聊天页面
│   ├── login.html        # 管理员登录页面
│   ├── admin_dashboard.html # 管理员控制面板
│   └── admin_change_password.html # 修改密码页面
└── static/               # 静态资源
## 贡献指南

1. 提交问题前请先搜索现有问题
2. 为每个新功能或修复创建单独的分支
3. 提交Pull Request前确保代码通过测试
4. 遵循现有的代码风格和结构

## 安全注意事项

1. 请务必修改SECRET_KEY为强密钥
2. 首次登录后立即修改默认管理员密码
3. 考虑使用HTTPS部署以保护通信安全
4. 不要在公共网络上使用默认配置

## 许可证

本项目采用 MIT 许可证，详情请见 LICENSE 文件。

## 支持与反馈

如有任何问题或建议，请提交Issue或联系项目维护者。    