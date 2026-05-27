/**
 * Afford Equity → Yipi Deal Bridge
 * ────────────────────────────────────────────────────────────────
 * Triggered by FunnelFlo/GHL Workflow when a contact enters the
 * "Referral" stage in the "Afford Equity" pipeline.
 *
 * Pipeline ID : 7QwFP4czBrjMTw6akTsR
 * Location ID : DwNygVvFAvEKH2LJJfl9
 *
 * Flow:
 *   FunnelFlo Webhook → this bridge → fetch contact notes from GHL API
 *   → separate PII → ML-KEM768 encrypt via Knish.IO
 *   → HMAC sign → POST to Yipi /api/webhooks/deals/ingest
 *
 * Deploy to: Netlify Functions, Vercel, Railway, or Render
 * Node 20+ required (native fetch + crypto)
 * ─────────────────────────────────────────────────────────────────
 */

import 'dotenv/config';
import { createHmac, randomUUID } from 'node:crypto';
import { Wallet } from '@wishknish/knishio-client-ts';

// ─── CONFIG ──────────────────────────────────────────────────────
const YIPI_BASE =
  process.env.YIPI_ENV === 'production'
    ? 'https://yipicircles.com'
    : 'https://sandbox.yipicircles.com';

const YIPI_API_KEY        = process.env.YIPI_API_KEY;
const YIPI_SIGNING_SECRET = process.env.YIPI_SIGNING_SECRET;
const YIPI_APP_TYPE       = process.env.YIPI_APP_TYPE || 'heaa_track_a';

const GHL_API_KEY         = process.env.GHL_API_KEY;       // pit-35e00dfb-...
const GHL_LOCATION_ID     = process.env.GHL_LOCATION_ID;   // DwNygVvFAvEKH2LJJfl9
const GHL_PIPELINE_ID     = process.env.GHL_PIPELINE_ID;   // 7QwFP4czBrjMTw6akTsR

const BRIDGE_SECRET       = process.env.BRIDGE_SECRET;

const GHL_HEADERS = {
  Authorization: `Bearer ${GHL_API_KEY}`,
  'Content-Type': 'application/json',
  Version: '2021-07-28',
};

// Cache platform pubkey — rarely changes
let _platformPubkey = null;

// ─── YIPI: FETCH PLATFORM ENCRYPTION KEY ─────────────────────────
async function getPlatformPubkey() {
  if (_platformPubkey) return _platformPubkey;
  const res = await fetch(`${YIPI_BASE}/api/public/platform-key`);
  if (!res.ok) throw new Error(`Yipi pubkey fetch failed: ${res.status}`);
  const { pubkey } = await res.json();
  _platformPubkey = pubkey;
  console.log('[bridge] Fetched Yipi platform pubkey');
  return pubkey;
}

// ─── GHL: FETCH FULL CONTACT RECORD ──────────────────────────────
// The GHL webhook gives us a snapshot — we fetch the full record for
// custom fields (property address, loan amount, etc.)
async function fetchContact(contactId) {
  const res = await fetch(
    `https://services.leadconnectorhq.com/contacts/${contactId}`,
    { headers: GHL_HEADERS }
  );
  if (!res.ok) {
    console.warn(`GHL contact fetch failed ${res.status} for ${contactId}`);
    return null;
  }
  const data = await res.json();
  return data.contact || data;
}

// ─── GHL: FETCH CONTACT NOTES ────────────────────────────────────
// Notes are NOT in the webhook payload — must be fetched separately.
// Notes are critical to the deal — they often contain the referral
// context, borrower situation, and deal notes from agents.
async function fetchNotes(contactId) {
  try {
    const res = await fetch(
      `https://services.leadconnectorhq.com/contacts/${contactId}/notes`,
      { headers: GHL_HEADERS }
    );
    if (!res.ok) {
      console.warn(`GHL notes fetch failed ${res.status} for ${contactId}`);
      return [];
    }
    const data = await res.json();
    const notes = (data.notes || []).sort(
      (a, b) => new Date(b.dateAdded) - new Date(a.dateAdded)
    );
    console.log(`[bridge] Fetched ${notes.length} notes for contact ${contactId}`);
    return notes.map((n) => ({
      id:   n.id,
      body: n.body,
      user: n.userId || null,
      date: n.dateAdded,
    }));
  } catch (err) {
    console.warn('[bridge] Notes fetch error:', err.message);
    return [];
  }
}

// ─── GHL: FLATTEN CUSTOM FIELDS ──────────────────────────────────
// GHL returns custom fields as an array of {id, value} objects.
// We flatten to a key→value map using the field key names.
function flattenCustomFields(contact) {
  const map = {};
  const fields = contact.customFields || contact.customField || [];
  fields.forEach((f) => {
    const key = f.fieldKey || f.key || f.id;
    if (key && f.value !== null && f.value !== undefined && f.value !== '') {
      map[key] = f.value;
    }
  });
  return map;
}

// ─── ENCRYPT PII WITH KNISH.IO ───────────────────────────────────
async function encryptPii(sensitiveData, pubkey) {
  // Seed is stable per org. Do NOT use contact-specific data as seed.
  const wallet = new Wallet({ secret: `afford-equity-yipi-originator` });
  const encrypted = await wallet.encryptMessage(sensitiveData, pubkey);
  return {
    cipher_text:    encrypted.cipherText,
    encrypted_data: encrypted.encryptedMessage,
  };
}

// ─── SIGN AND POST TO YIPI ───────────────────────────────────────
async function postToYipi(payload) {
  const bodyStr  = JSON.stringify(payload);
  // CRITICAL: strip trailing newline before signing
  const bodyWire = bodyStr.replace(/\n$/, '');

  const ts   = Math.floor(Date.now() / 1000);
  const idem = randomUUID();

  const headers = {
    'x-api-key':       YIPI_API_KEY,
    'Content-Type':    'application/json',
    'Idempotency-Key': idem,
  };

  if (YIPI_SIGNING_SECRET) {
    const sig = createHmac('sha256', YIPI_SIGNING_SECRET)
      .update(`${ts}.`)
      .update(bodyWire)
      .digest('hex');
    headers['X-Yipi-Timestamp'] = String(ts);
    headers['X-Yipi-Signature'] = `sha256=${sig}`;
  }

  const res  = await fetch(`${YIPI_BASE}/api/webhooks/deals/ingest`, {
    method:  'POST',
    headers,
    body:    bodyWire,
  });

  const json = await res.json();

  if (json._warnings?.auto_relocated_keys?.length) {
    console.warn(
      '[bridge] ⚠️  Yipi auto-relocated these fields (they should be in encrypted_pii):',
      json._warnings.auto_relocated_keys
    );
  }

  return { status: res.status, body: json };
}

// ─── BUILD YIPI PAYLOAD ───────────────────────────────────────────
function buildPayload(contact, customFields, opportunity, notes, encryptedPii) {

  // ── Format all notes into a single deal-notes string ───────────
  // This is the referral context from agents — critical to the deal
  const dealNotes = notes.length
    ? notes
        .map((n) => {
          const dateStr = n.date
            ? new Date(n.date).toLocaleDateString('en-US', {
                month: 'short', day: 'numeric', year: 'numeric',
              })
            : 'No date';
          return `--- ${dateStr} ---\n${n.body}`;
        })
        .join('\n\n')
    : null;

  // ── Opportunity value → loan amount ────────────────────────────
  const loanAmount =
    customFields['loan_amount']       ? Number(customFields['loan_amount'])       :
    customFields['requested_amount']  ? Number(customFields['requested_amount'])  :
    opportunity.monetaryValue         ? Number(opportunity.monetaryValue)         :
    null;

  // ── Build application_data (PLAINTEXT ONLY — no PII here) ───────
  const application_data = {
    // ── Borrower (name is OK plaintext per Yipi docs) ────────────
    first_name: contact.firstName || contact.first_name || '',
    last_name:  contact.lastName  || contact.last_name  || '',

    // ── Property routing fields ───────────────────────────────────
    property_address: customFields['property_address'] || contact.address1    || '',
    property_city:    customFields['property_city']    || contact.city        || '',
    property_state:   customFields['property_state']   || contact.state       || '',
    property_zip:     customFields['property_zip']     || contact.postalCode  || '',
    property_type:    customFields['property_type']    || '',

    // ── Deal fields ───────────────────────────────────────────────
    loan_type:              customFields['loan_type']   || 'home_equity',
    requested_loan_amount:  loanAmount,
    application_flow:       'referral',

    // ── Source tracking ───────────────────────────────────────────
    lead_source:        contact.source || 'GHL-Referral',
    referral_stage:     'referral',
    ghl_pipeline:       'Afford Equity',
    ghl_pipeline_id:    GHL_PIPELINE_ID,
    ghl_opportunity_id: opportunity.id   || null,
    ghl_contact_id:     contact.id,

    // ── Property details (from custom fields) ─────────────────────
    ...(customFields['bedrooms']    && { bedrooms:       Number(customFields['bedrooms'])    }),
    ...(customFields['bathrooms']   && { bathrooms:      Number(customFields['bathrooms'])   }),
    ...(customFields['year_built']  && { year_built:     Number(customFields['year_built'])  }),
    ...(customFields['sqft'] ||
        customFields['square_footage'] ? {
          square_footage: Number(customFields['sqft'] || customFields['square_footage'])
        } : {}),

    // ── Deal notes — referral context from AE agents ──────────────
    // This is the most important field for deal context.
    // Contains all notes added by agents in FunnelFlo.
    deal_notes: dealNotes,
    notes_count: notes.length,

    // ── Consent flags ─────────────────────────────────────────────
    contact_consent: true,
    state_eligible:  true,
  };

  // Strip nulls and empty strings
  Object.keys(application_data).forEach((k) => {
    if (application_data[k] === null ||
        application_data[k] === undefined ||
        application_data[k] === '') {
      delete application_data[k];
    }
  });

  return {
    user_id:                     contact.id,  // idempotency — same contact = same deal
    app_type:                    YIPI_APP_TYPE,
    integration_payload_version: '1.0.0',
    application_data,
    encrypted_pii:               encryptedPii,
  };
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────
export async function handler(req, res) {

  // 1. Verify bridge secret (set this in the GHL webhook header)
  const incomingSecret = req.headers['x-bridge-secret'];
  if (BRIDGE_SECRET && incomingSecret !== BRIDGE_SECRET) {
    console.warn('[bridge] Rejected — bad bridge secret');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // 2. Parse body
  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  // GHL sends contact data in different shapes depending on trigger type
  const contactId = body?.contact?.id || body?.contactId;
  if (!contactId) {
    return res.status(400).json({ error: 'No contactId in payload' });
  }

  console.log(`[bridge] New referral — contactId: ${contactId}`);

  try {
    // 3. Fetch full contact data + notes in parallel
    const [fullContact, notes] = await Promise.all([
      fetchContact(contactId),
      fetchNotes(contactId),
    ]);

    const contact      = fullContact || body.contact || {};
    const customFields = flattenCustomFields(contact);
    const opportunity  = body.opportunity || {};

    // 4. Build encrypted PII block
    //    Phone + email + DOB + financial fields go here — NEVER in application_data
    const sensitiveFields = {
      // ── Contact PII ──────────────────────────────────────────
      email: contact.email || body.contact?.email || null,
      phone: contact.phone || body.contact?.phone || null,

      // ── Identity ─────────────────────────────────────────────
      ...(contact.dateOfBirth && { date_of_birth: contact.dateOfBirth }),
      ...(customFields['date_of_birth'] && { date_of_birth: customFields['date_of_birth'] }),

      // ── Financial (from custom fields if captured) ────────────
      ...(customFields['credit_score']        && { credit_score:              Number(customFields['credit_score'])        }),
      ...(customFields['annual_income']       && { annual_income:             Number(customFields['annual_income'])       }),
      ...(customFields['monthly_income']      && { annual_income:             Number(customFields['monthly_income']) * 12 }),
      ...(customFields['mortgage_balance']    && { current_mortgage_balance:  Number(customFields['mortgage_balance'])   }),
      ...(customFields['estimated_value']     && { estimated_property_value:  Number(customFields['estimated_value'])    }),
      ...(customFields['home_value']          && { estimated_property_value:  Number(customFields['home_value'])         }),
      ...(customFields['ssn_last_four']       && { ssn_last_four:             customFields['ssn_last_four']               }),

      // ── Consent audit trail ───────────────────────────────────
      disclosure_acceptances: {
        terms:   { accepted_at: new Date().toISOString() },
        privacy: { accepted_at: new Date().toISOString() },
      },
    };

    // Remove nulls
    Object.keys(sensitiveFields).forEach((k) => {
      if (sensitiveFields[k] === null || sensitiveFields[k] === undefined) {
        delete sensitiveFields[k];
      }
    });

    // 5. Fetch platform pubkey + encrypt PII
    const pubkey      = await getPlatformPubkey();
    const encryptedPii = await encryptPii(sensitiveFields, pubkey);

    // 6. Assemble full Yipi payload
    const yipiPayload = buildPayload(
      contact, customFields, opportunity, notes, encryptedPii
    );

    console.log(
      `[bridge] Submitting to Yipi — user_id: ${yipiPayload.user_id}`,
      `| notes: ${notes.length}`,
      `| address: ${yipiPayload.application_data.property_address || 'unknown'}`
    );

    // 7. Post to Yipi
    const { status, body: yipiRes } = await postToYipi(yipiPayload);

    if (status === 201 || status === 200) {
      console.log(
        `[bridge] ✅ Success — dealId: ${yipiRes.dealId}`,
        `| duplicate: ${yipiRes.duplicate}`
      );
      return res.status(200).json({
        success:   true,
        dealId:    yipiRes.dealId,
        duplicate: yipiRes.duplicate,
        message:   yipiRes.message,
      });
    }

    console.error(`[bridge] ❌ Yipi error ${status}:`, yipiRes);
    return res.status(502).json({ success: false, yipiStatus: status, yipiError: yipiRes });

  } catch (err) {
    console.error('[bridge] Fatal error:', err);
    return res.status(500).json({ error: err.message });
  }
}

// ─── LOCAL DEV SERVER ─────────────────────────────────────────────
// node --experimental-vm-modules bridge.js
// POST http://localhost:3099 with a sample GHL webhook body
if (process.argv[1]?.endsWith('bridge.js')) {
  const { createServer } = await import('node:http');
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', async () => {
      req.body = raw;
      const mock = {
        _code: 200,
        status(c) { this._code = c; return this; },
        json(d)   { res.writeHead(this._code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(d, null, 2)); },
      };
      await handler(req, mock);
    });
  });
  server.listen(3099, () => console.log('🌉 Bridge dev server → http://localhost:3099'));
}
