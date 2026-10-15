
'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

class IntentGuardContract extends Contract {
    async InitLedger(ctx) {
        console.log('IntentGuard ledger initialized');
    }

    async RecordAuditEvent(ctx, eventJson) {
        const event = JSON.parse(eventJson);

        const requiredFields = [
            'event_id',
            'timestamp',
            'buyer_id',
            'supplier_id',
            'input_modality',
            'action_taken',
            'policy_reference',
            'raw_evidence_sha256',
            'redacted_diff_sha256',
            'intent_hmac_hash'
        ];

        for (const field of requiredFields) {
            if (
                event[field] === undefined ||
                event[field] === null ||
                event[field] === ''
            ) {
                throw new Error(`Missing required field: ${field}`);
            }
        }

        const hashFields = [
            'raw_evidence_sha256',
            'redacted_diff_sha256',
            'intent_hmac_hash'
        ];

        for (const field of hashFields) {
            if (!/^[a-fA-F0-9]{64}$/.test(event[field])) {
                throw new Error(`Invalid SHA-256 hash: ${field}`);
            }
        }

        if (!Array.isArray(event.risk_category_ids ?? [])) {
            throw new Error('risk_category_ids must be an array');
        }

        if (
            event.threat_detected === true &&
            event.action_taken === 'SAFE_EXECUTED'
        ) {
            throw new Error(
                'Threat detected events cannot be marked SAFE_EXECUTED'
            );
        }

        const eventId = event.event_id;
        const existing = await ctx.stub.getState(eventId);

        if (existing && existing.length > 0) {
            throw new Error(`Audit event already exists: ${eventId}`);
        }

        const storedEvent = {
            ...event,
            recorded_at: new Date(
                ctx.stub.getTxTimestamp().seconds.low * 1000
            ).toISOString()
        };

        await ctx.stub.putState(
            eventId,
            Buffer.from(JSON.stringify(storedEvent))
        );

        return JSON.stringify({
            event_id: eventId,
            recorded: true,
            transaction_id: ctx.stub.getTxID()
        });
    }

    async ReadAuditEvent(ctx, eventId) {
        const data = await ctx.stub.getState(eventId);

        if (!data || data.length === 0) {
            throw new Error(`Audit event not found: ${eventId}`);
        }

        return data.toString();
    }

    async GetAllAuditEvents(ctx) {
        const iterator = await ctx.stub.getStateByRange('', '');
        const results = [];

        try {
            while (true) {
                const result = await iterator.next();

                if (result.value && result.value.value) {
                    results.push({
                        key: result.value.key,
                        record: JSON.parse(
                            result.value.value.toString('utf8')
                        )
                    });
                }

                if (result.done) {
                    break;
                }
            }
        } finally {
            await iterator.close();
        }

        return JSON.stringify(results);
    }
}

module.exports = IntentGuardContract;
