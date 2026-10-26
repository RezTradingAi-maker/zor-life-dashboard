// server.js - Backend Rasmi StudyAI Malaysia
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const { PrismaClient } = require('@prisma/client');
const { OpenAI } = require('openai');

const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'studyai_secure_jwt_secret_2026';
const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;

app.use(express.json());
app.use(cors());

// Rate Limiting
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(globalLimiter);

// Multer Storage untuk Dokumen
const uploadDir = './uploads/documents';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `doc-${Date.now()}${path.extname(file.originalname)}`)
  }),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Middleware JWT Auth
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token pengesahan diperlukan.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token tidak sah atau telah luput.' });
    req.user = user;
    next();
  });
}

// Middleware Admin RBAC
async function requireAdmin(req, res, next) {
  verifyToken(req, res, async () => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user || user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Akses ditolak. Memerlukan peranan Pentadbir.' });
    }
    req.adminUser = user;
    next();
  });
}

// ================= AUTH ROUTES =================
app.post('/api/v1/auth/signup', async (req, res) => {
  try {
    const { email, name, password, level } = req.body;
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Emel telah berdaftar.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, name, passwordHash }
    });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: 'Gagal mendaftar akaun.' });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Emel atau kata laluan tidak sah.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role, tier: user.subscriptionTier } });
  } catch (error) {
    res.status(500).json({ error: 'Gagal log masuk.' });
  }
});

app.get('/api/v1/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ error: 'Pengguna tidak dijumpai.' });
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: 'Ralat pelayan.' });
  }
});

// ================= AI TUTOR ADAPTIF =================
app.post('/api/v1/ai/tutor', verifyToken, async (req, res) => {
  try {
    const { prompt, context } = req.body;
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (user.aiUsageCount >= user.aiUsageLimit) {
      return res.status(403).json({ error: 'Had kuota AI bulanan telah tamat. Sila naiktaraf pelan.' });
    }

    if (!openai) return res.status(503).json({ error: 'Perkhidmatan OpenAI belum dikonfigurasi di pelayan.' });

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: `Anda adalah Tutor Adaptif StudyAI Malaysia untuk subjek ${context?.subject || 'Am'}. Terangkan langkah demi langkah dan berikan soalan pengukuhan.` },
        { role: 'user', content: prompt }
      ],
      temperature: 0.3
    });

    await prisma.user.update({
      where: { id: user.id },
      data: { aiUsageCount: { increment: 1 } }
    });

    res.json({ success: true, reply: completion.choices[0].message.content });
  } catch (error) {
    res.status(500).json({ error: 'Gagal memproses permintaan AI.' });
  }
});

// ================= LIBRARY & DOCUMENTS =================
app.get('/api/v1/library', verifyToken, async (req, res) => {
  try {
    const items = await prisma.libraryItem.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' }
    });
    res.json({ success: true, items });
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengambil perpustakaan.' });
  }
});

// ================= ADMIN DASHBOARD =================
app.get('/api/v1/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [totalUsers, plusUsers, usageAgg] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { subscriptionTier: 'Plus' } }),
      prisma.user.aggregate({ _sum: { aiUsageCount: true, aiUsageLimit: true } })
    ]);

    res.json({
      success: true,
      stats: {
        totalAccounts: totalUsers,
        plusSubscribers: plusUsers,
        totalAIQueriesUsed: usageAgg._sum.aiUsageCount || 0,
        totalAIQuotaAllocated: usageAgg._sum.aiUsageLimit || 0,
        systemStatus: { database: 'Connected', aiEngine: openai ? 'Active' : 'Disabled' }
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengambil statistik admin.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 StudyAI Malaysia Server berjalan pada port ${PORT}`));
