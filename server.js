const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

// Cabeçalhos de segurança HTTP
app.use(helmet());
app.use(express.json({ limit: '10kb' })); 
app.use(cors({ origin: '*' })); // Substitua pelo seu domínio em produção

// Limite de requisições por IP (Marco Civil / Anti-Bot)
const agendamentoLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { status: 'error', message: 'Muitas tentativas. Tente novamente em 15 minutos.' }
});

// Inicialização do Banco de Dados
const db = new sqlite3.Database('./agendamentos.db', (err) => {
    if (err) console.error('Erro ao conectar ao banco:', err.message);
    else console.log('Banco de dados SQLite conectado.');
});

// Tabela com trava de segurança para data_hora e registro de IP
db.run(`
    CREATE TABLE IF NOT EXISTS agendamentos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT NOT NULL,
        telefone TEXT NOT NULL,
        data_hora TEXT UNIQUE NOT NULL,
        observacao TEXT,
        ip_usuario TEXT NOT NULL,
        aceitou_termos INTEGER NOT NULL,
        criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

const sanitizar = (str) => String(str).replace(/[<>]/g, '').trim();

// Rota principal de agendamento
app.post('/api/agendar', agendamentoLimiter, (req, res) => {
    const { nome, email, telefone, dataHora, observacao, honeypot, aceitouTermos } = req.body;
    const ipUsuario = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // 1. Armadilha Anti-Bot
    if (honeypot) {
        return res.status(400).json({ status: 'error', message: 'Requisição inválida.' });
    }

    // 2. Validação LGPD de Consentimento
    if (!aceitouTermos) {
        return res.status(400).json({ status: 'error', message: 'O consentimento dos termos é obrigatório.' });
    }

    // 3. Validação de Campos Obrigatórios
    if (!nome || !email || !telefone || !dataHora) {
        return res.status(400).json({ status: 'error', message: 'Preencha todos os campos obrigatórios.' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ status: 'error', message: 'Formato de e-mail inválido.' });
    }

    // 4. Sanitização de Entrada
    const nomeLimpo = sanitizar(nome);
    const emailLimpo = sanitizar(email);
    const telefoneLimpo = sanitizar(telefone);
    const dataHoraLimpa = sanitizar(dataHora);
    const obsLimpa = observacao ? sanitizar(observacao) : '';

    // 5. Inserção com Prepared Statement (Previne SQL Injection e Overbooking)
    const sql = `
        INSERT INTO agendamentos (nome, email, telefone, data_hora, observacao, ip_usuario, aceitou_termos) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.run(sql, [nomeLimpo, emailLimpo, telefoneLimpo, dataHoraLimpa, obsLimpa, ipUsuario, aceitouTermos ? 1 : 0], function (err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ status: 'error', message: 'Este horário acabou de ser reservado. Escolha outro.' });
            }
            return res.status(500).json({ status: 'error', message: 'Erro interno no servidor.' });
        }

        return res.status(201).json({
            status: 'success',
            message: 'Agendamento realizado com sucesso!',
            protocolo: this.lastID
        });
    });
});

app.listen(PORT, () => console.log(`Servidor rodando com segurança na porta ${PORT}`));
