import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const eventTypes = {
  'Request for Quotation': 'erpnext.rfq.changed',
  'Purchase Order': 'erpnext.po.changed',
  'purchase.order': 'odoo.purchase.changed',
  'sale.order': 'odoo.sale.changed',
};

function matches(actual, expected) {
  return typeof actual === 'string' && timingSafeEqual(
    createHash('sha256').update(actual).digest(),
    createHash('sha256').update(expected).digest(),
  );
}

export function webhook(source) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') return res.status(405).json({error: 'Use POST'});
    const secret = source === 'erpnext' ? process.env.ERPNEXT_WEBHOOK_SECRET : process.env.ODOO_WEBHOOK_SECRET;
    const token = process.env.HUB_API_TOKEN;
    if (!secret || !token) return res.status(503).json({error: 'Webhook integration is not configured'});

    let body;
    try {
      const chunks = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 65536) return res.status(413).json({error: 'Webhook exceeds 64 KiB'});
        chunks.push(chunk);
      }
      const raw = Buffer.concat(chunks);
      const signature = source === 'erpnext'
        ? createHmac('sha256', secret).update(raw).digest('base64')
        : secret;
      const supplied = source === 'erpnext' ? req.headers['x-frappe-webhook-signature'] : req.query.key;
      if (!matches(supplied, signature)) return res.status(401).json({error: 'Invalid webhook authentication'});
      body = JSON.parse(raw.toString('utf8'));
    } catch {
      return res.status(400).json({error: 'Invalid JSON'});
    }

    const model = source === 'erpnext' ? body?.doctype : body?._model;
    const documentId = source === 'erpnext' ? body?.name : body?._id;
    const modified = source === 'erpnext' ? body?.modified : body?.write_date;
    const state = source === 'erpnext' ? body?.docstatus : body?.state;
    const type = typeof model === 'string' && Object.hasOwn(eventTypes, model) && eventTypes[model];
    if (!type || !type.startsWith(source + '.') || !['string', 'number'].includes(typeof documentId)
      || !String(documentId).trim() || String(documentId).length > 180 || typeof modified !== 'string'
      || !modified || modified.length > 80 || !['string', 'number'].includes(typeof state)) {
      return res.status(422).json({error: 'Unsupported document or missing document ID, modification time, or state'});
    }
    const externalId = body.entailinkTransactionId;
    const digest = (parts) => createHash('sha256').update(JSON.stringify(parts)).digest('hex');
    const transactionId = typeof externalId === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(externalId)
      ? externalId : 'erp:' + digest([source, model, documentId]).slice(0, 32);
    const eventId = 'erp:' + digest([source, model, documentId, modified, state]).slice(0, 40);
    try {
      const response = await fetch('https://hub.entailink.com/api/events/publish', {
        method: 'POST',
        headers: {authorization: 'Bearer ' + token, 'content-type': 'application/json'},
        body: JSON.stringify({eventId, transactionId, type, payload: {source, model, documentId, modified, state}}),
        redirect: 'error',
        signal: AbortSignal.timeout(12000),
      });
      if (response.status !== 201) return res.status(502).json({error: 'Hub did not acknowledge publication', hubStatus: response.status});
      const {topic, partition, offset} = await response.json();
      return res.status(201).json({eventId, transactionId, topic, partition, offset});
    } catch {
      return res.status(502).json({error: 'Could not confirm Kafka publication through Hub'});
    }
  };
}
