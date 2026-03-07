require('dotenv').config();
const express = require('express');
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const nodemailer = require('nodemailer');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_pocket_key_123';

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // Use STARTTLS
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    connectionTimeout: 10000, // 10 seconds
    greetingTimeout: 10000,
    socketTimeout: 15000
});

app.use(cors());
app.use(express.json());

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// 0. Auth Routes
app.post('/api/register/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) return res.status(400).json({ error: "Email already in use" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + 15);

        // Upsert OTP record
        const existingOtp = await prisma.otpVerification.findUnique({ where: { email } });
        if (existingOtp) {
            await prisma.otpVerification.update({ where: { email }, data: { otp, expiresAt } });
        } else {
            await prisma.otpVerification.create({ data: { email, otp, expiresAt } });
        }

        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'PocketSaver Registration OTP',
                text: `Your registration OTP is ${otp}. It expires in 15 minutes.`
            });
            res.json({ message: "OTP sent to your email." });
        } else {
            console.log(`[DEV MODE] Registration OTP for ${email} is ${otp}`);
            res.json({ message: "OTP generated (Check server console, email not configured in .env)." });
        }
    } catch (error) {
        console.error("Registration OTP Error:", error);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, otp } = req.body;

        if (!otp) return res.status(400).json({ error: "OTP is required" });

        const otpRecord = await prisma.otpVerification.findUnique({ where: { email } });
        if (!otpRecord || otpRecord.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }
        if (otpRecord.expiresAt < new Date()) {
            return res.status(400).json({ error: "OTP has expired" });
        }

        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) return res.status(400).json({ error: "Email already in use" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { name, email, password: hashedPassword }
        });

        await prisma.otpVerification.delete({ where: { email } });

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to register" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return res.status(401).json({ error: "Invalid credentials" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to login" });
    }
});

app.post('/api/forgot-password/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return res.status(404).json({ error: "User not found with this email" });

        // Generate 6 digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save to user with 15 min expiry
        const expiry = new Date();
        expiry.setMinutes(expiry.getMinutes() + 15);

        await prisma.user.update({
            where: { email },
            data: { resetOtp: otp, resetOtpExpiry: expiry }
        });

        // Try sending email, gracefully fallback if not configured
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'PocketSaver Password Reset OTP',
                text: `Your password reset OTP is ${otp}. It expires in 15 minutes.`
            });
            res.json({ message: "OTP sent to your email." });
        } else {
            console.log(`[DEV MODE] OTP for ${email} is ${otp}`);
            res.json({ message: "OTP generated (Check server console, email not configured in .env)." });
        }
    } catch (error) {
        console.error("OTP Error:", error);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return res.status(404).json({ error: "User not found with this email" });

        if (!user.resetOtp || user.resetOtp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }

        if (!user.resetOtpExpiry || user.resetOtpExpiry < new Date()) {
            return res.status(400).json({ error: "OTP has expired" });
        }

        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: "Password must be at least 6 characters" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { email },
            data: {
                password: hashedPassword,
                resetOtp: null,
                resetOtpExpiry: null
            }
        });

        res.json({ message: "Password reset successfully. You can now login with your new password." });
    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(500).json({ error: "Failed to reset password" });
    }
});

// Routes
// 1. Get dashboard summary
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const transactions = await prisma.transaction.findMany({
            where: { userId }
        });

        const personalIncome = transactions.filter(t => t.type === 'INCOME' && t.context !== 'BUSINESS').reduce((sum, t) => sum + t.amount, 0);
        const personalExpenses = transactions.filter(t => t.type === 'EXPENSE' && t.context !== 'BUSINESS').reduce((sum, t) => sum + t.amount, 0);
        const savings = personalIncome - personalExpenses;

        const businessIncome = transactions.filter(t => t.type === 'INCOME' && t.context === 'BUSINESS').reduce((sum, t) => sum + t.amount, 0);
        const businessExpenses = transactions.filter(t => t.type === 'EXPENSE' && t.context === 'BUSINESS').reduce((sum, t) => sum + t.amount, 0);
        const businessProfit = businessIncome - businessExpenses;

        let savingScore = 0;
        if (personalIncome > 0) {
            const percentageSaved = (savings / personalIncome) * 100;
            if (percentageSaved >= 20) savingScore = 95;
            else if (percentageSaved >= 10) savingScore = 75;
            else if (percentageSaved > 0) savingScore = 50;
            else savingScore = 30;
        }

        res.json({
            income: personalIncome,
            expenses: personalExpenses,
            savings,
            savingScore,
            businessSummary: {
                income: businessIncome,
                expenses: businessExpenses,
                profit: businessProfit
            },
            transactions
        });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch dashboard data" });
    }
});

// 2. Add Transaction
app.post('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const { type, amount, category, note, date, context } = req.body;
        const userId = req.user.id;

        const transaction = await prisma.transaction.create({
            data: {
                userId,
                type,
                amount: parseFloat(amount),
                category,
                note,
                date: date ? new Date(date) : undefined,
                context: context || 'PERSONAL'
            }
        });

        res.status(201).json(transaction);
    } catch (error) {
        console.error("Transaction Error:", error);
        res.status(500).json({ error: "Failed to add transaction" });
    }
});

// 3. Get Advisor Hints (Refined for Accuracy)
app.get('/api/advisor', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const transactions = await prisma.transaction.findMany({ where: { userId } });

        const income = transactions.filter(t => t.type === 'INCOME');
        const totalIncome = income.reduce((sum, t) => sum + t.amount, 0);

        const expenses = transactions.filter(t => t.type === 'EXPENSE');
        const totalExpenses = expenses.reduce((sum, t) => sum + t.amount, 0);

        let insights = [];

        // 1. Ratio Insight (More accurate thresholds)
        if (totalIncome > 0) {
            const ratio = totalExpenses / totalIncome;
            const percent = Math.round(ratio * 100);

            if (ratio >= 1.2) {
                insights.push(`🚨 Debt Warning: You have spent ${percent}% of your income! You are spending significantly more than you earn. Stop all non-essential spending immediately.`);
            } else if (ratio >= 1.0) {
                insights.push(`⚠️ Overspending Alert: You have spent ${percent}% of your income. You are at zero savings or entering debt this month.`);
            } else if (ratio >= 0.8) {
                insights.push(`📉 High Spend Alert: You've spent ${percent}% of your income. You only have ${100 - percent}% left for savings.`);
            } else if (ratio >= 0.5) {
                insights.push(`💡 Savings Tip: You've spent ${percent}% of your income. Try to keep it below 50% to reach your saving goals faster.`);
            } else {
                insights.push(`✅ Excellent Progress: You've only spent ${percent}% of your income. Your savings rate is very healthy!`);
            }
        } else if (totalExpenses > 0) {
            insights.push("⚠️ Alert: You have recorded expenses but no income yet. Make sure to add your income to see your savings ratio.");
        }

        // 2. Category specific insight
        if (expenses.length > 0) {
            const categories = expenses.reduce((acc, t) => {
                acc[t.category] = (acc[t.category] || 0) + t.amount;
                return acc;
            }, {});

            const topCategory = Object.keys(categories).reduce((a, b) => categories[a] > categories[b] ? a : b);
            const topAmount = categories[topCategory];

            if (topAmount > 0) {
                insights.push(`📊 Analysis: Your highest spending is on "${topCategory}" (₹${topAmount}). Can you cut this by 10% next month?`);
            }
        }

        if (insights.length === 0) {
            insights.push("Start adding your income and expenses to get personalized AI tips!");
        }

        res.json({
            insights,
            debug: {
                totalIncome,
                totalExpenses,
                ratio: totalIncome > 0 ? (totalExpenses / totalIncome) : 0
            }
        });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch advisor hints" });
    }
});

// 4. Get Budget Prediction
app.get('/api/predict', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const transactions = await prisma.transaction.findMany({
            where: { userId, type: 'EXPENSE' }
        });

        if (transactions.length === 0) return res.json({ prediction: 0 });

        const total = transactions.reduce((sum, t) => sum + t.amount, 0);
        const average = total / 30; // Simple daily average for MVP
        res.json({ prediction: Math.round(average * 30) });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch prediction" });
    }
});

// 5. Goals APIs
app.get('/api/goals', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const goals = await prisma.goal.findMany({ where: { userId } });
        res.json(goals);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch goals" });
    }
});

app.post('/api/goals', authenticateToken, async (req, res) => {
    try {
        const { name, targetAmount, deadline } = req.body;
        const userId = req.user.id;
        const goal = await prisma.goal.create({
            data: {
                userId,
                name,
                targetAmount: parseFloat(targetAmount),
                savedAmount: 0,
                deadline: deadline ? new Date(deadline) : null
            }
        });
        res.status(201).json(goal);
    } catch (error) {
        res.status(500).json({ error: "Failed to create goal" });
    }
});

// 6. Challenges (Read-only for MVP)
app.get('/api/challenges', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        // In a real app, this might calculate based on transaction patterns
        // For MVP, we return a few default ones
        res.json([
            { id: 1, name: "No Spend Day", progress: 0, status: "Active" },
            { id: 2, name: "Save ₹50 Daily", progress: 20, status: "Active" }
        ]);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch challenges" });
    }
});

// 6. Month-wise History
app.get('/api/transactions/history', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const transactions = await prisma.transaction.findMany({
            where: { userId },
            orderBy: { date: 'desc' }
        });

        // Group by Month Year (e.g., "March 2026")
        const grouped = transactions.reduce((acc, t) => {
            const monthNames = ["January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"
            ];
            const d = new Date(t.date);
            const key = `${monthNames[d.getMonth()]} ${d.getFullYear()}`;

            if (!acc[key]) acc[key] = { month: key, income: 0, expense: 0, items: [] };

            if (t.type === 'INCOME') acc[key].income += t.amount;
            else acc[key].expense += t.amount;

            acc[key].items.push(t);
            return acc;
        }, {});

        res.json(Object.values(grouped));
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch history" });
    }
});

// 7. Update Transaction
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { type, amount, category, note, date, context } = req.body;
        const userId = req.user.id;

        // Verify ownership
        const existing = await prisma.transaction.findUnique({ where: { id } });
        if (!existing || existing.userId !== userId) {
            return res.status(403).json({ error: "Unauthorized or transaction not found" });
        }

        const updated = await prisma.transaction.update({
            where: { id },
            data: {
                type,
                amount: parseFloat(amount),
                category,
                note,
                date: date ? new Date(date) : undefined,
                context: context || 'PERSONAL'
            }
        });

        res.json(updated);
    } catch (error) {
        console.error("Update Transaction Error:", error);
        res.status(500).json({ error: "Failed to update transaction" });
    }
});

// 8. Delete Transaction
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;

        // Verify ownership
        const existing = await prisma.transaction.findUnique({ where: { id } });
        if (!existing || existing.userId !== userId) {
            return res.status(403).json({ error: "Unauthorized or transaction not found" });
        }

        await prisma.transaction.delete({ where: { id } });
        res.json({ message: "Transaction deleted successfully" });
    } catch (error) {
        console.error("Delete Transaction Error:", error);
        res.status(500).json({ error: "Failed to delete transaction" });
    }
});

// 9. Gamification: Update Game Score
app.post('/api/user/game-score', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { points, coins } = req.body;

        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: {
                points: { increment: points || 0 },
                totalCoins: { increment: coins || 0 },
                // Every 100 points rewarded gives a +1 to saving score (up to 100)
                savingScore: {
                    set: Math.min(100, (await prisma.user.findUnique({ where: { id: userId } })).savingScore + Math.floor((points || 0) / 100))
                }
            }
        });

        res.json({
            points: updatedUser.points,
            totalCoins: updatedUser.totalCoins,
            savingScore: updatedUser.savingScore
        });
    } catch (error) {
        console.error("Game Score Error:", error);
        res.status(500).json({ error: "Failed to update game score" });
    }
});

// 10. Get User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, name: true, email: true, points: true, totalCoins: true, savingScore: true }
        });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch profile" });
    }
});

// 11. Change Password
app.put('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) return res.status(404).json({ error: "User not found" });

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) return res.status(400).json({ error: "Incorrect current password" });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword }
        });

        res.json({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Change Password Error:", error);
        res.status(500).json({ error: "Failed to change password" });
    }
});

// ─── BUDGET APIs ───────────────────────────────────────────────────
// Get budgets for current month
app.get('/api/budgets', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const month = new Date().toISOString().slice(0, 7); // "2026-03"
        const budgets = await prisma.budget.findMany({ where: { userId, month } });
        res.json(budgets);
    } catch (e) { res.status(500).json({ error: 'Failed to fetch budgets' }); }
});

// Get budget status (spend vs limit per category) for current month
app.get('/api/budgets/status', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const month = new Date().toISOString().slice(0, 7);
        const startOfMonth = new Date(`${month}-01`);
        const endOfMonth = new Date(startOfMonth.getFullYear(), startOfMonth.getMonth() + 1, 0, 23, 59, 59);

        const [budgets, transactions] = await Promise.all([
            prisma.budget.findMany({ where: { userId, month } }),
            prisma.transaction.findMany({
                where: { userId, type: 'EXPENSE', context: 'PERSONAL', date: { gte: startOfMonth, lte: endOfMonth } }
            })
        ]);

        const spendMap = {};
        transactions.forEach(t => { spendMap[t.category] = (spendMap[t.category] || 0) + t.amount; });

        const status = budgets.map(b => ({
            ...b,
            spent: spendMap[b.category] || 0,
            percent: Math.round(((spendMap[b.category] || 0) / b.monthlyLimit) * 100)
        }));
        res.json(status);
    } catch (e) { res.status(500).json({ error: 'Failed to fetch budget status' }); }
});

// Create or update budget for a category
app.post('/api/budgets', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { category, monthlyLimit } = req.body;
        const month = new Date().toISOString().slice(0, 7);

        const existing = await prisma.budget.findFirst({ where: { userId, category, month } });
        let budget;
        if (existing) {
            budget = await prisma.budget.update({ where: { id: existing.id }, data: { monthlyLimit: parseFloat(monthlyLimit) } });
        } else {
            budget = await prisma.budget.create({ data: { userId, category, monthlyLimit: parseFloat(monthlyLimit), month } });
        }
        res.json(budget);
    } catch (e) { res.status(500).json({ error: 'Failed to save budget' }); }
});

app.delete('/api/budgets/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        await prisma.budget.delete({ where: { id } });
        res.json({ message: 'Budget deleted' });
    } catch (e) { res.status(500).json({ error: 'Failed to delete budget' }); }
});

// ─── RECURRING TRANSACTIONS ─────────────────────────────────────────
app.get('/api/recurring', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const items = await prisma.recurringTransaction.findMany({ where: { userId }, orderBy: { amount: 'desc' } });
        res.json(items);
    } catch (e) { res.status(500).json({ error: 'Failed to fetch recurring' }); }
});

app.post('/api/recurring', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { type, amount, category, context, note, frequency } = req.body;
        const item = await prisma.recurringTransaction.create({
            data: { userId, type, amount: parseFloat(amount), category, context: context || 'PERSONAL', note, frequency: frequency || 'MONTHLY' }
        });
        res.json(item);
    } catch (e) { res.status(500).json({ error: 'Failed to create recurring' }); }
});

app.delete('/api/recurring/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        await prisma.recurringTransaction.delete({ where: { id } });
        res.json({ message: 'Deleted' });
    } catch (e) { res.status(500).json({ error: 'Failed to delete' }); }
});

// Process recurring: creates this month's transactions for all recurring items that haven't run yet
app.post('/api/recurring/process', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const now = new Date();
        const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
        const items = await prisma.recurringTransaction.findMany({ where: { userId } });
        let created = 0;
        for (const item of items) {
            const hasRun = item.lastRun && item.lastRun >= monthStart;
            if (!hasRun) {
                await prisma.transaction.create({
                    data: { userId, type: item.type, amount: item.amount, category: item.category, context: item.context, note: `[Auto] ${item.note || item.category}`, date: now }
                });
                await prisma.recurringTransaction.update({ where: { id: item.id }, data: { lastRun: now } });
                created++;
            }
        }
        res.json({ created });
    } catch (e) { res.status(500).json({ error: 'Failed to process recurring' }); }
});

// ─── ANALYTICS ──────────────────────────────────────────────────────
// 6-month income/expense trend
app.get('/api/analytics/trends', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const now = new Date();
        const result = [];

        for (let i = 5; i >= 0; i--) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const start = new Date(d.getFullYear(), d.getMonth(), 1);
            const end = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59);

            const txns = await prisma.transaction.findMany({ where: { userId, context: 'PERSONAL', date: { gte: start, lte: end } } });
            const income = txns.filter(t => t.type === 'INCOME').reduce((s, t) => s + t.amount, 0);
            const expense = txns.filter(t => t.type === 'EXPENSE').reduce((s, t) => s + t.amount, 0);

            result.push({ month: `${monthNames[d.getMonth()]}`, income, expense, savings: income - expense });
        }
        res.json(result);
    } catch (e) { res.status(500).json({ error: 'Failed to get trends' }); }
});

// Weekly heatmap: sum of daily spending for last 28 days
app.get('/api/analytics/heatmap', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const now = new Date();
        const start = new Date(now);
        start.setDate(start.getDate() - 27);
        start.setHours(0, 0, 0, 0);

        const txns = await prisma.transaction.findMany({
            where: { userId, type: 'EXPENSE', date: { gte: start } }
        });

        const map = {};
        txns.forEach(t => {
            const key = t.date.toISOString().split('T')[0];
            map[key] = (map[key] || 0) + t.amount;
        });

        // Build 28-day array
        const days = [];
        for (let i = 27; i >= 0; i--) {
            const d = new Date(now);
            d.setDate(d.getDate() - i);
            const key = d.toISOString().split('T')[0];
            days.push({ date: key, amount: map[key] || 0 });
        }
        res.json(days);
    } catch (e) { res.status(500).json({ error: 'Failed to get heatmap' }); }
});

// ─── CSV EXPORT ─────────────────────────────────────────────────────
app.get('/api/transactions/export', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { context } = req.query; // optional: PERSONAL or BUSINESS
        const where = { userId };
        if (context) where.context = context;

        const txns = await prisma.transaction.findMany({ where, orderBy: { date: 'desc' } });
        const header = 'Date,Type,Amount,Category,Context,Note\n';
        const rows = txns.map(t =>
            `${t.date.toISOString().split('T')[0]},${t.type},${t.amount},${t.category},${t.context},"${(t.note || '').replace(/"/g, '\\"')}"`
        ).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="transactions.csv"');
        res.send(header + rows);
    } catch (e) { res.status(500).json({ error: 'Failed to export' }); }
});

// ─── STREAK UPDATE ──────────────────────────────────────────────────
app.post('/api/user/streak', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await prisma.user.findUnique({ where: { id: userId } });
        const now = new Date();
        const yesterday = new Date(now); yesterday.setDate(yesterday.getDate() - 1);
        const lastActive = user.lastActive;

        let newStreak = user.streak;
        if (!lastActive || lastActive < yesterday) {
            // Check if yesterday had zero over-spending (savings >= 0)
            const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const txns = await prisma.transaction.findMany({ where: { userId, context: 'PERSONAL', date: { gte: start } } });
            const income = txns.filter(t => t.type === 'INCOME').reduce((s, t) => s + t.amount, 0);
            const expense = txns.filter(t => t.type === 'EXPENSE').reduce((s, t) => s + t.amount, 0);
            newStreak = (income >= expense) ? (user.streak || 0) + 1 : 0;
        }

        const updated = await prisma.user.update({ where: { id: userId }, data: { streak: newStreak, lastActive: now } });
        res.json({ streak: updated.streak });
    } catch (e) { res.status(500).json({ error: 'Failed to update streak' }); }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Backend server running on http://0.0.0.0:${PORT}`);
});
