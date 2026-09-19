const Database = require('better-sqlite3');
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

if (fs.existsSync('.env')) {
    for (const line of fs.readFileSync('.env', 'utf8').split(/\r?\n/)) {
        const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
        if (match && !process.env[match[1]]) process.env[match[1]] = match[2];
    }
}

const adminPin = process.env.ADMIN_PIN;
const adminSecret = process.env.ADMIN_SECRET;
if (!adminPin || !adminSecret) {
    throw new Error('ADMIN_PIN va ADMIN_SECRET .env faylida bo‘lishi kerak');
}
const sessions = new Map();
const failedLogins = new Map();

function hashPin(pin) {
    return crypto.createHmac('sha256', adminSecret).update(pin).digest('hex');
}

function isAdmin(req) {
    const token = (req.headers.cookie || '').match(/volt_admin=([^;]+)/)?.[1];
    return Boolean(token && sessions.has(token) && sessions.get(token) > Date.now());
}

function requireAdmin(req, res, next) {
    if (!isAdmin(req)) return res.status(401).json({ xabar: 'Admin avtorizatsiyasi kerak' });
    next();
}


// ===============================
// DATABASE
// ===============================

const db = new Database('mahsulotlar.db');

db.exec(`
    CREATE TABLE IF NOT EXISTS mahsulotlar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nomi TEXT NOT NULL,
        kategoriya TEXT NOT NULL,
        soni INTEGER NOT NULL,
        narxi INTEGER NOT NULL
    )
`);


// ===============================
// BOSHLANG‘ICH MAHSULOTLAR
// ===============================

const jamiMahsulot = db
    .prepare('SELECT COUNT(*) AS soni FROM mahsulotlar')
    .get();

if (jamiMahsulot.soni === 0) {

    const qoshish = db.prepare(`
        INSERT INTO mahsulotlar
        (nomi, kategoriya, soni, narxi)
        VALUES (?, ?, ?, ?)
    `);

    qoshish.run(
        'Arduino Uno',
        'Arduino',
        14,
        85000
    );

    qoshish.run(
        'HC-SR04',
        'Sensor',
        20,
        35000
    );

    qoshish.run(
        'Servo SG90',
        'Motor',
        15,
        30000
    );

    qoshish.run(
        'L298N',
        'Motor driver',
        10,
        45000
    );
}


// ===============================
// EXPRESS
// ===============================

const app = express();

app.use(express.json());
app.use(express.static('public', { etag: false, maxAge: 0 }));

app.post('/admin/login', (req, res) => {
    const ip = req.ip;
    const attempts = failedLogins.get(ip) || { count: 0, blockedUntil: 0 };
    if (attempts.blockedUntil > Date.now()) {
        return res.status(429).json({ xabar: 'Juda ko‘p urinish. Keyinroq qayta urinib ko‘ring.' });
    }

    const providedHash = hashPin(String(req.body.pin || ''));
    const valid = crypto.timingSafeEqual(
        Buffer.from(providedHash, 'hex'),
        Buffer.from(hashPin(adminPin), 'hex')
    );
    if (!valid) {
        attempts.count += 1;
        if (attempts.count >= 5) attempts.blockedUntil = Date.now() + 60_000;
        failedLogins.set(ip, attempts);
        return res.status(401).json({ xabar: 'PIN kod noto‘g‘ri' });
    }

    failedLogins.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + 30 * 60 * 1000);
    res.setHeader('Set-Cookie', `volt_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`);
    res.json({ xabar: 'Admin panelga kirildi' });
});

app.post('/admin/logout', (req, res) => {
    const token = (req.headers.cookie || '').match(/volt_admin=([^;]+)/)?.[1];
    if (token) sessions.delete(token);
    res.setHeader('Set-Cookie', 'volt_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    res.json({ xabar: 'Sessiya yopildi' });
});


// ===============================
// BOSH SAHIFA
// ===============================

app.get('/', (req, res) => {

    res.send('Robototexnika ombori ishlayapti!');

});


// ===============================
// BARCHA MAHSULOTLAR
// GET /mahsulotlar
// ===============================

app.get('/mahsulotlar', (req, res) => {

    const mahsulotlar = db
        .prepare('SELECT * FROM mahsulotlar')
        .all();

    res.json(mahsulotlar);

});
// ===============================
// BITTA MAHSULOT
// GET /mahsulotlar/:id
// ===============================

app.get('/mahsulotlar/:id', (req, res) => {

    const id = Number(req.params.id);

    const mahsulot = db
        .prepare('SELECT * FROM mahsulotlar WHERE id = ?')
        .get(id);

    if (!mahsulot) {

        return res.status(404).json({
            xabar: 'Mahsulot topilmadi'
        });

    }

    res.json(mahsulot);

});


// ===============================
// YANGI MAHSULOT QO‘SHISH
// POST /mahsulotlar
// ===============================

app.post('/mahsulotlar', requireAdmin, (req, res) => {

    const {
        nomi,
        kategoriya,
        soni,
        narxi
    } = req.body;


    const natija = db
        .prepare(`
            INSERT INTO mahsulotlar
            (nomi, kategoriya, soni, narxi)
            VALUES (?, ?, ?, ?)
        `)
        .run(
            nomi,
            kategoriya,
            soni,
            narxi
        );


    const yangiMahsulot = db
        .prepare('SELECT * FROM mahsulotlar WHERE id = ?')
        .get(natija.lastInsertRowid);


    res.status(201).json({

        xabar: "Mahsulot muvaffaqiyatli qo'shildi",

        mahsulot: yangiMahsulot

    });

});
// ===============================
// MAHSULOTNI O‘ZGARTIRISH
// PUT /mahsulotlar/:id
// ===============================

app.put('/mahsulotlar/:id', requireAdmin, (req, res) => {

    const id = Number(req.params.id);

    const {
        nomi,
        kategoriya,
        soni,
        narxi
    } = req.body;


    const mavjud = db
        .prepare('SELECT * FROM mahsulotlar WHERE id = ?')
        .get(id);


    if (!mavjud) {

        return res.status(404).json({
            xabar: 'Mahsulot topilmadi'
        });

    }


    db.prepare(`
        UPDATE mahsulotlar
        SET
            nomi = ?,
            kategoriya = ?,
            soni = ?,
            narxi = ?
        WHERE id = ?
    `)
        .run(
            nomi,
            kategoriya,
            soni,
            narxi,
            id
        );


    const yangilangan = db
        .prepare('SELECT * FROM mahsulotlar WHERE id = ?')
        .get(id);


    res.json({

        xabar: "Mahsulot muvaffaqiyatli o'zgartirildi",

        mahsulot: yangilangan

    });

});


// ===============================
// MAHSULOTNI O‘CHIRISH
// DELETE /mahsulotlar/:id
// ===============================

app.delete('/mahsulotlar/:id', requireAdmin, (req, res) => {

    const id = Number(req.params.id);


    const mahsulot = db
        .prepare('SELECT * FROM mahsulotlar WHERE id = ?')
        .get(id);


    if (!mahsulot) {

        return res.status(404).json({
            xabar: 'Mahsulot topilmadi'
        });

    }


    db.prepare(
        'DELETE FROM mahsulotlar WHERE id = ?'
    ).run(id);


    res.json({

        xabar: "Mahsulot muvaffaqiyatli o'chirildi",

        mahsulot: mahsulot

    });

});


// ===============================
// SERVER
// ===============================

app.listen(3000, () => {

    console.log('Server 3000-portda ishlamoqda');

});
