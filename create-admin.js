const bcrypt = require('bcryptjs');
const { initDatabase, getDb, saveDatabase } = require('./config/database');

async function createAdmin() {
  try {
    await initDatabase();
    const db = getDb();
    
    // Проверяем, есть ли уже админ
    const checkStmt = db.prepare('SELECT id FROM users WHERE username = ? AND role = ?');
    checkStmt.bind(['admin', 'admin']);
    const exists = checkStmt.step();
    checkStmt.free();
    
    if (exists) {
      console.log('⚠ Администратор "admin" уже существует!');
      process.exit(0);
    }
    
    // Создаем админа
    const passwordHash = bcrypt.hashSync('admin123', 10);
    const stmt = db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)');
    stmt.run(['admin', 'admin@cyberpunk.net', passwordHash, 'admin']);
    stmt.free();
    
    saveDatabase();
    
    console.log('');
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║     ✓ АДМИНИСТРАТОР СОЗДАН УСПЕШНО!         ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log('║  Логин: admin                                ║');
    console.log('║  Пароль: admin123                            ║');
    console.log('║                                              ║');
    console.log('║  Откройте: http://localhost:3000/admin/login ');
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');
    
    process.exit(0);
  } catch (err) {
    console.error('Ошибка при создании админа:', err);
    process.exit(1);
  }
}

createAdmin();