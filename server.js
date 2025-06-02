const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');

const app = express();
const port = 3000;

// 中间件
app.use(cors());
app.use(express.json());
// 托管 html 静态文件
app.use(express.static(__dirname, { extensions: ['html'] }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 数据库连接
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'yan',
  database: 'skincare'
});

db.connect(err => {
  if (err) console.error('数据库连接失败:', err);
  else console.log('成功连接到数据库');
});

// 注册接口
app.post('/register', (req, res) => {
  const { username, password, skin_type } = req.body;
  if (!username || !password) return res.status(400).json({ message: '用户名和密码是必填项' });

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ message: '查询失败' });
    if (results.length > 0) return res.status(400).json({ message: '用户名已存在' });

    const hashedPassword = bcrypt.hashSync(password, 8);
    db.query(
      'INSERT INTO users (username, password, skin_type) VALUES (?, ?, ?)',
      [username, hashedPassword, skin_type || '中性'],
      (err, result) => {
        if (err) return res.status(500).json({ message: '注册失败' });
        res.json({ message: '注册成功', userId: result.insertId });
      }
    );
  });
});

// 登录接口
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: '用户名和密码是必填项' });

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ message: '查询失败' });
    if (results.length === 0) return res.status(400).json({ message: '用户名不存在' });

    const user = results[0];
    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) return res.status(401).json({ message: '密码错误' });

    res.json({
      message: '登录成功',
      user: {
        id: user.id,
        username: user.username,
        skin_type: user.skin_type,
        created_at: user.created_at
      }
    });
  });
});

// 上传图片配置
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
    cb(null, filename);
  }
});
const upload = multer({ storage });

// 添加皮肤记录
app.post('/api/skin-records', upload.single('photo'), (req, res) => {
  const { user_id, oil_level, acne_level, dryness_level, is_public } = req.body;
  const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
  const record_date = new Date().toISOString().split('T')[0];

  db.query(`
    INSERT INTO skin_records (user_id, record_date, oil_level, acne_level, dryness_level, photo_url, is_public)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    user_id, record_date, oil_level || null, acne_level || null, dryness_level || null, photo_url, is_public === 'true'
  ], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: '服务器错误' });
    res.json({ success: true, message: '记录成功', recordId: result.insertId });
  });
});

// 查询用户皮肤记录
app.get('/api/skin-records/:userId', (req, res) => {
  db.query(`
    SELECT id, record_date, oil_level, acne_level, dryness_level, photo_url, is_public, created_at
    FROM skin_records
    WHERE user_id = ?
    ORDER BY record_date DESC
  `, [req.params.userId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: '服务器错误' });
    res.json({ success: true, records: results });
  });
});

// 删除皮肤记录
app.delete('/api/skin-records/:id', (req, res) => {
  const { id } = req.params;
  const { user_id } = req.query;

  if (!user_id) return res.status(400).json({ success: false, message: '缺少用户ID' });

  db.query('DELETE FROM skin_records WHERE id = ? AND user_id = ?', [id, user_id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: '服务器错误' });
    if (result.affectedRows === 0) return res.status(403).json({ success: false, message: '无权删除' });
    res.json({ success: true });
  });
});

// 查询公开用户
app.get('/api/public-users', (req, res) => {
  db.query(`
    SELECT u.id, u.username, COUNT(s.id) AS public_count
    FROM users u
    JOIN skin_records s ON u.id = s.user_id
    WHERE s.is_public = 1
    GROUP BY u.id
    ORDER BY public_count DESC
  `, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: '查询失败' });
    res.json({ success: true, users: results });
  });
});

// 查询公开记录
app.get('/api/public-records/:userId', (req, res) => {
  db.query(`
    SELECT id, record_date, oil_level, acne_level, dryness_level, photo_url
    FROM skin_records
    WHERE user_id = ? AND is_public = 1
    ORDER BY record_date DESC
  `, [req.params.userId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: '查询失败' });
    res.json({ success: true, records: results });
  });
});

// 用户资料修改
app.put('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const { username, skin_type, password } = req.body;

  const fields = [];
  const values = [];

  if (username) { fields.push('username = ?'); values.push(username); }
  if (skin_type) { fields.push('skin_type = ?'); values.push(skin_type); }
  if (password && password.trim() !== '') {
    const hashedPassword = bcrypt.hashSync(password, 8);
    fields.push('password = ?');
    values.push(hashedPassword);
  }

  if (fields.length === 0) return res.status(400).json({ success: false, message: '没有提供任何需要更新的字段' });
  values.push(userId);

  db.query(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values, (err) => {
    if (err) return res.status(500).json({ success: false, message: '更新失败' });

    db.query('SELECT id, username, skin_type, created_at FROM users WHERE id = ?', [userId], (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: '查询失败' });
      res.json({ success: true, user: rows[0] });
    });
  });
});

// 评论接口（每个用户的公开记录共用一个评论区）
app.get('/api/comments/:userId', (req, res) => {
  const userId = req.params.userId;
  // 查询评论及点赞数
  const sql = `
    SELECT c.id, c.content, c.created_at, u.username,
      (SELECT COUNT(*) FROM replies r WHERE r.comment_id = c.id) AS reply_count,
      (SELECT COUNT(*) FROM likes l JOIN skin_records sr ON l.record_id = sr.id WHERE sr.user_id = ? AND l.record_id = sr.id) AS like_count
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.target_user_id = ?
    ORDER BY c.created_at DESC
  `;
  db.query(sql, [userId, userId], (err, comments) => {
    if (err) return res.status(500).json({ success: false, message: '查询失败' });
    if (!comments || comments.length === 0) return res.json({ success: true, comments: [] });
    // 查询所有评论的回复
    const commentIds = comments.map(c => c.id);
    db.query('SELECT r.*, u.username FROM replies r LEFT JOIN users u ON r.user_id = u.id WHERE comment_id IN (?)', [commentIds], (err2, replies) => {
      if (err2) return res.status(500).json({ success: false, message: '加载回复失败' });
      const replyMap = {};
      replies.forEach(r => {
        if (!replyMap[r.comment_id]) replyMap[r.comment_id] = [];
        replyMap[r.comment_id].push(r);
      });
      const final = comments.map(c => ({
        ...c,
        replies: replyMap[c.id] || []
      }));
      res.json({ success: true, comments: final });
    });
  });
});

app.post('/api/comments', (req, res) => {
  const { user_id, target_user_id, content } = req.body;
  if (!user_id || !target_user_id || !content) return res.status(400).json({ success: false, message: '缺少必要参数' });

  db.query(`
    INSERT INTO comments (user_id, target_user_id, content, created_at)
    VALUES (?, ?, ?, NOW())
  `, [user_id, target_user_id, content], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: '插入失败' });
    // 新增：评论时发送通知
    if (user_id !== target_user_id) {
      sendNotification({ user_id: target_user_id, type: 'comment', from_user_id: user_id, comment_id: result.insertId });
    }
    res.json({ success: true, message: '评论成功' });
  });
});

// 点赞/取消点赞皮肤记录
app.post('/api/like-record', (req, res) => {
  const { user_id, record_id } = req.body;
  if (!user_id || !record_id) {
    return res.json({ success: false, message: '缺少参数' });
  }
  db.query('SELECT id FROM likes WHERE user_id = ? AND record_id = ?', [user_id, record_id], (err, results) => {
    if (err) return res.json({ success: false, message: '查询失败' });
    if (results.length > 0) {
      db.query('DELETE FROM likes WHERE user_id = ? AND record_id = ?', [user_id, record_id], (err2) => {
        if (err2) return res.json({ success: false, message: '取消点赞失败' });
        res.json({ success: true, liked: false, message: '已取消点赞' });
      });
    } else {
      db.query('INSERT INTO likes (user_id, record_id) VALUES (?, ?)', [user_id, record_id], (err2) => {
        if (err2) return res.json({ success: false, message: '点赞失败' });
        // 新增：点赞时发送通知
        db.query('SELECT user_id FROM skin_records WHERE id = ?', [record_id], (err3, rows) => {
          if (!err3 && rows && rows[0] && rows[0].user_id !== user_id) {
            sendNotification({ user_id: rows[0].user_id, type: 'like', from_user_id: user_id, record_id });
          }
        });
        res.json({ success: true, liked: true, message: '点赞成功' });
      });
    }
  });
});

// 新增评论回复功能
app.post('/api/reply-comment', (req, res) => {
  const { user_id, parent_comment_id, content } = req.body;
  if (!user_id || !parent_comment_id || !content) {
    return res.json({ success: false, message: '缺少参数' });
  }
  db.query('INSERT INTO replies (comment_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())', [parent_comment_id, user_id, content], (err) => {
    if (!err) {
      // 查找原评论作者
      db.query('SELECT user_id FROM comments WHERE id = ?', [parent_comment_id], (err2, rows) => {
        if (!err2 && rows && rows[0] && rows[0].user_id !== user_id) {
          sendNotification({ user_id: rows[0].user_id, type: 'reply', from_user_id: user_id, comment_id: parent_comment_id });
        }
      });
    }
    if (err) return res.json({ success: false, message: '回复失败' });
    res.json({ success: true });
  });
});

// ========== 消息通知相关 ========== //
// 通用通知插入函数
function sendNotification({ user_id, type, from_user_id, record_id = null, comment_id = null }) {
  db.query(
    'INSERT INTO notifications (user_id, type, from_user_id, record_id, comment_id) VALUES (?, ?, ?, ?, ?)',
    [user_id, type, from_user_id, record_id, comment_id],
    (err) => {
      if (err) console.error('通知插入失败:', err);
    }
  );
}

// 获取用户未读通知
app.get('/api/notifications/:userId', (req, res) => {
  const userId = req.params.userId;
  db.query(
    `SELECT n.*, u.username AS from_username, c.content AS comment_content
     FROM notifications n
     LEFT JOIN users u ON n.from_user_id = u.id
     LEFT JOIN comments c ON n.comment_id = c.id
     WHERE n.user_id = ? AND n.is_read = 0
     ORDER BY n.id DESC
     LIMIT 50`,
    [userId],
    (err, results) => {
      if (err) return res.json({ success: false, message: '查询失败' });
      res.json({ success: true, notifications: results });
    }
  );
});

// 标记所有通知为已读
app.post('/api/notifications/read', (req, res) => {
  const { user_id } = req.body;
  db.query('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [user_id], (err) => {
    if (err) return res.status(500).json({ success: false, message: '更新失败' });
    res.json({ success: true });
  });
});

// 功能：根路径重定向到登录页
// Function: Redirect root path to login page
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// 启动服务器
app.listen(port, () => {
  console.log(`服务器正在运行在 http://localhost:${port}`);
});
