
'use strict';

const express = require('express');
const { connectToFabric } = require('./fabric');

const app = express();
app.use(express.json());
require('dotenv').config();

function requireApiKey(req, res, next) {
    const providedKey = req.headers['x-api-key'];

    if (!process.env.INTENTGUARD_API_KEY ||
        providedKey !== process.env.INTENTGUARD_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    next();
}
let fabric;

app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'IntentGuard Blockchain API' });
});

app.post('/audit-events', requireApiKey, async (req, res) => {
    try {
        const result = await fabric.contract.submitTransaction(
            'RecordAuditEvent',
            JSON.stringify(req.body)
        );

        const text = Buffer.from(result).toString('utf8');
        res.status(201).json(JSON.parse(text));
    } catch (error) {
        console.error('Failed to record audit event:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.get('/audit-events/:event_id',requireApiKey, async (req, res) => {
    try {
        const result = await fabric.contract.evaluateTransaction(
            'ReadAuditEvent',
            req.params.event_id
        );

        const text = Buffer.from(result).toString('utf8');
        res.json(JSON.parse(text));
    } catch (error) {
        console.error('Failed to retrieve audit event:', error.message);
        res.status(404).json({ error: 'Audit event not found' });
    }
});

async function start() {
    fabric = await connectToFabric();

    const server = app.listen(8000, '0.0.0.0', () => {
        console.log('IntentGuard API listening on port 8000');
    });

    async function shutdown() {
        server.close();
        fabric.gateway.close();
        fabric.client.close();
        process.exit(0);
    }

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

start().catch((error) => {
    console.error('Failed to start IntentGuard API:', error);
    process.exit(1);
});
