/**
 * Afford Equity → Partner Lead-Flow Bridge  (v2)
 * ─────────────────────────────────────────────────────────────────
 * Triggered by FunnelFlo/GHL Workflows (tag-based as of v2; the legacy
 * stage-based workflow continues to work via the "/" catch-all).
 *
 * Pipeline ID : 7QwFP4czBrjMTw6akTsR
 * Location ID : DwNygVvFAvEKH2LJJfl9
 *
 * Routes (dispatched by server.js):
 *   POST /yipi/submit       tag flow — deal type REQUIRED (from tags or customData)
 *   POST /yipi/withdraw     remove a submitted deal (Yipi originator withdraw)
 *   POST /soldandstay/submit  Google Sheet logging only (Shannon / Sold & Stay)
 *   POST /stayfrank/submit  stub until StayFrank API spec is final
 *   POST /  (legacy)        same as /yipi/submit but deal type falls back to
 *                           YIPI_APP_TYPE — preserves v1 behavior exactly
 *
 * Deal types (Yips process), exactly one per Yipi tag submission:
 *   deal-new-slb → new_slb        deal-exit-slb → exit_slb
 *   deal-new-fractional → new_fractional   deal-exit-fractional → exit_fractional
 *
 * Flow (submit):
 *   GHL Webhook → fetch contact + notes from GHL API → separate PII
 *   → ML-KEM768 encrypt via Knish.IO → HMAC sign → POST Yipi ingest
 *   → fire-and-forget Google Sheets log
 *
 * Flow (withdraw):
 *   GHL Webhook → GET /api/deals/by-correlation/{contactId}
 *   → guard in-flight status → POST /api/deals/{id}/originator-status
 *     { status: "withdrawn" }  (per Yipi release 2026-05-28)
 *
 * Node 20+ required (native fetch + crypto)
 * ─────────────────────────────────────────────────────────────────
 */

import 'dotenv/config';
import { createHmac, randomUUID, randomBytes } from 'node:crypto';
import { Wallet } from '@wishknish/knishio-client-ts';

// ─── CONFIG ──────────────────────────────────────────────────────
const YIPI_BASE =
  process.env.YIPI_BASE_URL || // explicit override (testing / future envs)
  (process.env.YIPI_ENV === 'production'
    ? 'https://yipicircles.com'
    : 'https://sandbox.yipicircles.com');

const YIPI_API_KEY = process.env.YIPI_API_KEY;
const YIPI_SIGNING_SECRET = process.env.YIPI_SIGNING_SECRET;
const YIPI_APP_TYPE = process.env.YIPI_APP_TYPE || 'heaa_track_a'; // legacy fallback only

const GHL_API_KEY = process.env.GHL_API_KEY;
const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID;
const GHL_PIPELINE_ID = process.env.GHL_PIPELINE_ID;

const BRIDGE_SECRET = process.env.BRIDGE_SECRET;

const SHEETS_URL =
  process.env.SHEETS_URL ||
  'https://script.google.com/macros/s/AKfycbx0kgbXBQckPA5lRPHcYplHcmIdH0fFB8jYRZUPNjaLw4idUh34KjNuZJ-56VJz8jyI/exec';

const GHL_HEADERS = {
  Authorization: `Bearer ${GHL_API_KEY}`,
  'Content-Type': 'application/json',
  Version: '2021-07-28',
};

// ─── DEAL TYPES (Yips process) ───────────────────────────────────
const DEAL_TYPE_TAGS = {
  'deal-new-slb': 'new_slb',
  'deal-exit-slb': 'exit_slb',
  'deal-new-fractional': 'new_fractional',
  'deal-exit-fractional': 'exit_fractional',
};
const DEAL_TYPE_CODES = new Set(Object.values(DEAL_TYPE_TAGS));

function normalizeTags(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.map((t) => String(t).trim().toLowerCase()).filter(Boolean);
  return String(raw).split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
}

/**
 * Resolve the deal type from (in priority order):
 *  1. customData.deal_type on the webhook payload (accepts "new_slb" / "New-SLB" / etc.)
 *  2. the contact's deal-type tags (webhook payload tags + GHL API contact tags)
 * Returns { code, source } or { error, tags }.
 */
function resolveDealType(body, contact) {
  const custom = body.customData || body.custom_data || {};
  const explicit = String(custom.deal_type || custom.dealType || body.deal_type || '')
    .trim().toLowerCase().replace(/-/g, '_');
  if (DEAL_TYPE_CODES.has(explicit)) return { code: explicit, source: 'customData' };

  const tags = [
    ...normalizeTags(body.tags || body.contact_tags),
    ...normalizeTags(contact?.tags),
  ];
  const matched = [...new Set(tags.filter((t) => DEAL_TYPE_TAGS[t]).map((t) => DEAL_TYPE_TAGS[t]))];
  if (matched.length === 1) return { code: matched[0], source: 'tags' };
  if (matched.length === 0) return { error: 'missing_deal_type', tags };
  return { error: 'multiple_deal_types', found: matched, tags };
}

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
async function fetchContact(contactId) {
  try {
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
  } catch (err) {
    console.warn('[bridge] Contact fetch error:', err.message);
    return null;
  }
}

// ─── GHL: FETCH CONTACT NOTES ────────────────────────────────────
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
      id: n.id,
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
  // Ephemeral sender wallet — only the platform (recipient) can decrypt.
  const wallet = new Wallet({ secret: randomBytes(32).toString('hex') });
  const encrypted = await wallet.encryptMessage(sensitiveData, pubkey);
  return {
    cipher_text: encrypted.cipherText,
    encrypted_data: encrypted.encryptedMessage,
  };
}

// ─── SIGNED REQUEST TO YIPI ──────────────────────────────────────
function yipiHeaders(bodyWire, withIdempotency = true) {
  const headers = {
    'x-api-key': YIPI_API_KEY,
  };
  if (withIdempotency) {
    headers['Content-Type'] = 'application/json';
    headers['Idempotency-Key'] = randomUUID();
  }
  if (YIPI_SIGNING_SECRET) {
    const ts = Math.floor(Date.now() / 1000);
    const sig = createHmac('sha256', YIPI_SIGNING_SECRET)
      .update(`${ts}.`)
      .update(bodyWire)
      .digest('hex');
    headers['X-Yipi-Timestamp'] = String(ts);
    headers['X-Yipi-Signature'] = `sha256=${sig}`;
  }
  return headers;
}

async function postToYipi(payload) {
  const bodyWire = JSON.stringify(payload).replace(/\n$/, '');
  const res = await fetch(`${YIPI_BASE}/api/webhooks/deals/ingest`, {
    method: 'POST',
    headers: yipiHeaders(bodyWire),
    body: bodyWire,
  });
  const json = await res.json();

  if (json._warnings?.auto_relocated_keys?.length) {
    console.warn(
      '[bridge] ⚠️ Yipi auto-relocated these fields:',
      json._warnings.auto_relocated_keys
    );
  }
  return { status: res.status, body: json };
}

async function yipiGet(path) {
  // For a GET the signed body is the empty string → HMAC input is `${ts}.`
  const res = await fetch(`${YIPI_BASE}${path}`, {
    headers: yipiHeaders('', false),
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, body: json };
}

async function yipiPost(path, payload) {
  const bodyWire = JSON.stringify(payload).replace(/\n$/, '');
  const res = await fetch(`${YIPI_BASE}${path}`, {
    method: 'POST',
    headers: yipiHeaders(bodyWire),
    body: bodyWire,
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON */ }
  // Retry once on retryable idempotency race
  if (res.status === 503 && json?.error?.code === 'idempotency_in_progress') {
    await new Promise((r) => setTimeout(r, 2000));
    return yipiPost(path, payload);
  }
  return { status: res.status, body: json };
}

// ─── BUILD YIPI PAYLOAD ───────────────────────────────────────────
function buildPayload(contact, customFields, opportunity, notes, encryptedPii, appType) {
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

  const loanAmount =
    customFields['loan_amount'] ? Number(customFields['loan_amount']) :
    customFields['requested_amount'] ? Number(customFields['requested_amount']) :
    opportunity.monetaryValue ? Number(opportunity.monetaryValue) :
    null;

  const application_data = {
    first_name: contact.firstName || contact.first_name || '',
    last_name: contact.lastName || contact.last_name || '',

    property_address: customFields['property_address'] || contact.address1 || '',
    property_city: customFields['property_city'] || contact.city || '',
    property_state: customFields['property_state'] || contact.state || '',
    property_zip: customFields['property_zip'] || contact.postalCode || contact.postal_code || '',
    property_type: customFields['property_type'] || '',

    loan_type: customFields['loan_type'] || 'home_equity',
    requested_loan_amount: loanAmount,
    application_flow: 'referral',

    lead_source: contact.source || 'GHL-Referral',
    referral_stage: 'referral',
    ghl_pipeline: 'Afford Equity',
    ghl_pipeline_id: GHL_PIPELINE_ID,
    ghl_opportunity_id: opportunity.id || null,
    ghl_contact_id: contact.id,

    ...(customFields['bedrooms'] && { bedrooms: Number(customFields['bedrooms']) }),
    ...(customFields['bathrooms'] && { bathrooms: Number(customFields['bathrooms']) }),
    ...(customFields['year_built'] && { year_built: Number(customFields['year_built']) }),
    ...(customFields['sqft'] ||
    customFields['square_footage'] ? {
      square_footage: Number(customFields['sqft'] || customFields['square_footage'])
    } : {}),

    deal_notes: dealNotes,
    notes_count: notes.length,

    contact_consent: true,
    state_eligible: true,
  };

  Object.keys(application_data).forEach((k) => {
    if (application_data[k] === null ||
        application_data[k] === undefined ||
        application_data[k] === '') {
      delete application_data[k];
    }
  });

  return {
    user_id: contact.id,
    app_type: appType,
    integration_payload_version: '2.0.0',
    application_data,
    encrypted_pii: encryptedPii,
  };
}

// ─── SHARED: AUTH + CONTACT ID EXTRACTION ────────────────────────
function authorize(req, res) {
  const incomingSecret = req.headers['x-bridge-secret'];
  if (BRIDGE_SECRET && incomingSecret !== BRIDGE_SECRET) {
    console.warn('[bridge] Rejected — bad bridge secret');
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}

function parseBody(req, res) {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    return body;
  } catch {
    res.status(400).json({ error: 'Invalid JSON' });
    return null;
  }
}

function extractContactId(body) {
  return (
    body?.contact?.id ||
    body?.contactId ||
    body?.contact_id ||
    body?.id ||
    body?.data?.contact?.id ||
    body?.data?.contactId
  );
}

// ─── HANDLER: YIPI SUBMIT ────────────────────────────────────────
// requireDealType=true on /yipi/submit (tag flow); false on legacy "/"
export async function handleYipiSubmit(req, res, { requireDealType }) {
  if (!authorize(req, res)) return;
  const body = parseBody(req, res);
  if (!body) return;

  console.log('[bridge] Incoming payload keys:', Object.keys(body || {}));
  console.log('[bridge] Payload snapshot:', JSON.stringify(body)?.slice(0, 600));

  const contactId = extractContactId(body);
  if (!contactId) {
    console.error('[bridge] No contactId found. Full payload:', JSON.stringify(body));
    return res.status(400).json({
      error: 'No contactId in payload',
      received: Object.keys(body || {}),
    });
  }

  console.log(`[bridge] New submission — contactId: ${contactId}`);

  try {
    // Fetch full contact data + notes in parallel
    const [fullContact, notes] = await Promise.all([
      fetchContact(contactId),
      fetchNotes(contactId),
    ]);

    const flatContact = {
      id: contactId,
      firstName: body.first_name || body.firstName || '',
      lastName: body.last_name || body.lastName || '',
      email: body.email || '',
      phone: body.phone || '',
      address1: body.address1 || body.full_address || '',
      city: body.city || '',
      state: body.state || '',
      postalCode: body.postal_code || body.postalCode || '',
      source: body.contact_source || body.source || '',
      customFields: [],
    };

    const contact = fullContact || body.contact || flatContact;
    if (!contact.id) contact.id = contactId;

    // Resolve deal type (tags / customData)
    const dt = resolveDealType(body, contact);
    let appType;
    if (dt.code) {
      appType = dt.code;
    } else if (!requireDealType) {
      appType = YIPI_APP_TYPE; // legacy behavior
    } else {
      console.warn(`[bridge] ${contactId} rejected: ${dt.error}`, JSON.stringify(dt.tags));
      return res.status(422).json({
        error: dt.error,
        message: dt.error === 'missing_deal_type'
          ? 'Add exactly one deal-type tag (deal-new-slb, deal-exit-slb, deal-new-fractional, deal-exit-fractional) BEFORE adding partner-yipi.'
          : `Contact has multiple deal-type tags (${dt.found.join(', ')}). Remove the wrong one, then re-add partner-yipi.`,
        tags_seen: dt.tags,
      });
    }

    const customFields = flattenCustomFields(contact);
    const opportunity = body.opportunity || {
      id: body.id || null,
      monetaryValue: body.lead_value || null,
    };

    // Build encrypted PII block
    const sensitiveFields = {
      email: contact.email || body.email || null,
      phone: contact.phone || body.phone || null,

      ...(contact.dateOfBirth && { date_of_birth: contact.dateOfBirth }),
      ...(customFields['date_of_birth'] && { date_of_birth: customFields['date_of_birth'] }),

      ...(customFields['credit_score'] && { credit_score: Number(customFields['credit_score']) }),
      ...(customFields['annual_income'] && { annual_income: Number(customFields['annual_income']) }),
      ...(customFields['monthly_income'] && { annual_income: Number(customFields['monthly_income']) * 12 }),
      ...(customFields['mortgage_balance'] && { current_mortgage_balance: Number(customFields['mortgage_balance']) }),
      ...(customFields['estimated_value'] && { estimated_property_value: Number(customFields['estimated_value']) }),
      ...(customFields['home_value'] && { estimated_property_value: Number(customFields['home_value']) }),
      ...(customFields['ssn_last_four'] && { ssn_last_four: customFields['ssn_last_four'] }),

      disclosure_acceptances: {
        terms: { accepted_at: new Date().toISOString() },
        privacy: { accepted_at: new Date().toISOString() },
      },
    };

    Object.keys(sensitiveFields).forEach((k) => {
      if (sensitiveFields[k] === null || sensitiveFields[k] === undefined) {
        delete sensitiveFields[k];
      }
    });

    // Encrypt + assemble + send
    const pubkey = await getPlatformPubkey();
    const encryptedPii = await encryptPii(sensitiveFields, pubkey);
    const yipiPayload = buildPayload(
      contact, customFields, opportunity, notes, encryptedPii, appType
    );

    console.log(
      `[bridge] Submitting to Yipi — user_id: ${yipiPayload.user_id}`,
      `| app_type: ${appType} (${dt.source || 'fallback'})`,
      `| name: ${yipiPayload.application_data.first_name} ${yipiPayload.application_data.last_name}`,
      `| notes: ${notes.length}`
    );

    const { status, body: yipiRes } = await postToYipi(yipiPayload);

    // Google Sheets log (fire-and-forget — never blocks Yipi response)
    logToSheet(contact, body, yipiPayload, notes, contactId, yipiRes, appType);

    if (status === 200 || status === 201 || status === 202) {
      console.log(
        `[bridge] ✅ Success — dealId: ${yipiRes.dealId}`,
        `| duplicate: ${yipiRes.duplicate}`
      );
      return res.status(200).json({
        success: true,
        dealId: yipiRes.dealId,
        deal_type: appType,
        duplicate: yipiRes.duplicate,
        message: yipiRes.message,
      });
    }

    console.error(`[bridge] ❌ Yipi error ${status}:`, JSON.stringify(yipiRes, null, 2));
    return res.status(502).json({ success: false, yipiStatus: status, yipiError: yipiRes });
  } catch (err) {
    console.error('[bridge] Fatal error:', err);
    return res.status(500).json({ error: err.message });
  }
}

// ─── HANDLER: YIPI DEALS LIST (visibility) ───────────────────────
// GET /yipi/deals?page=1&perPage=100&status=&search=&deal_type=
// Proxies Yipi's GET /api/deals so the Afford Equity dashboard can show
// every deal this API key has submitted, with live status.
export async function handleYipiDeals(req, res, query) {
  if (!authorize(req, res)) return;

  const params = new URLSearchParams();
  params.set('page', query.get('page') || '1');
  params.set('perPage', query.get('perPage') || '100');
  params.set('sortBy', query.get('sortBy') || 'created_at');
  params.set('sortDirection', query.get('sortDirection') || 'DESC');
  for (const k of ['status', 'search', 'deal_type', 'date_from', 'date_to']) {
    if (query.get(k)) params.set(k, query.get(k));
  }

  try {
    const out = await yipiGet(`/api/deals?${params.toString()}`);
    if (out.status !== 200) {
      console.error(`[bridge] deals list failed ${out.status}:`, JSON.stringify(out.body)?.slice(0, 400));
      return res.status(502).json({ success: false, yipiStatus: out.status, yipiError: out.body });
    }
    const data = out.body?.data || {};
    const items = (data.items || []).map((d) => ({
      dealId: d.id,
      external_id: d.external_id, // = GHL contact id when submitted via this bridge
      borrower_name: d.borrower_name,
      deal_type: d.deal_type,
      status: d.status,
      loan_amount: d.loan_amount,
      property_city: d.property_city,
      property_state: d.property_state,
      ingested_at: d.ingested_at,
      withdrawable: ['received', 'processing', 'active', 'under_review'].includes(d.status),
    }));
    return res.status(200).json({
      success: true,
      totalCount: data.totalCount ?? items.length,
      page: data.pagination?.page ?? 1,
      totalPages: data.pagination?.totalPages ?? 1,
      items,
    });
  } catch (err) {
    console.error('[bridge] Fatal error (deals list):', err);
    return res.status(500).json({ error: err.message });
  }
}

// ─── HANDLER: YIPI WITHDRAW (deal removal) ───────────────────────
// Accepts EITHER { dealId } (dashboard) OR a GHL webhook payload with a
// contact id (tag flow) — resolves to the deal and withdraws it.
export async function handleYipiWithdraw(req, res) {
  if (!authorize(req, res)) return;
  const body = parseBody(req, res);
  if (!body) return;

  const directDealId = body.dealId || body.deal_id;
  const contactId = extractContactId(body);
  if (!directDealId && !contactId) {
    return res.status(400).json({
      error: 'No dealId or contactId in payload',
      received: Object.keys(body || {}),
    });
  }

  const custom = body.customData || body.custom_data || {};
  const reason = body.reason || custom.withdraw_reason || custom.reason || 'Withdrawn by Afford Equity via CRM';

  try {
    // 1. Find the deal — by id (dashboard) or by correlation id (tag flow)
    const lookupPath = directDealId
      ? `/api/deals/${encodeURIComponent(String(directDealId))}`
      : `/api/deals/by-correlation/${encodeURIComponent(String(contactId))}`;
    const lookup = await yipiGet(lookupPath);
    if (lookup.status === 404) {
      console.warn(`[bridge] withdraw: no deal found (${directDealId || contactId})`);
      return res.status(404).json({
        success: false,
        error: 'deal_not_found',
        message: directDealId ? 'Deal not found on Yipi.' : 'No Yipi deal exists for this contact.',
      });
    }
    if (lookup.status !== 200) {
      console.error(`[bridge] withdraw lookup failed ${lookup.status}:`, JSON.stringify(lookup.body));
      return res.status(502).json({ success: false, yipiStatus: lookup.status, yipiError: lookup.body });
    }

    const deal = lookup.body?.data || {};
    const WITHDRAWABLE = ['received', 'processing', 'active', 'under_review'];
    if (!WITHDRAWABLE.includes(deal.status)) {
      console.warn(`[bridge] withdraw: deal ${deal.id} not withdrawable (status=${deal.status})`);
      return res.status(409).json({
        success: false,
        error: 'not_withdrawable',
        deal_status: deal.status,
        message: deal.status === 'withdrawn'
          ? 'Deal is already withdrawn.'
          : `Deal status is "${deal.status}" — only in-flight deals can be withdrawn.`,
      });
    }

    // 2. Withdraw
    const out = await yipiPost(`/api/deals/${deal.id}/originator-status`, {
      status: 'withdrawn',
      reason,
    });

    if (out.status === 200) {
      console.log(`[bridge] ✅ Withdrawn — deal ${deal.id} (contact ${contactId})`);
      return res.status(200).json({
        success: true,
        dealId: deal.id,
        previous_status: deal.status,
        message: 'Deal withdrawn from Yipi.',
      });
    }

    console.error(`[bridge] ❌ withdraw failed ${out.status}:`, JSON.stringify(out.body));
    return res.status(502).json({ success: false, yipiStatus: out.status, yipiError: out.body });
  } catch (err) {
    console.error('[bridge] Fatal error (withdraw):', err);
    return res.status(500).json({ error: err.message });
  }
}

// ─── HANDLER: SOLD & STAY (sheet logging only) ───────────────────
export async function handleSoldAndStaySubmit(req, res) {
  if (!authorize(req, res)) return;
  const body = parseBody(req, res);
  if (!body) return;

  const contactId = extractContactId(body);
  if (!contactId) {
    return res.status(400).json({ error: 'No contactId in payload', received: Object.keys(body || {}) });
  }

  try {
    const [fullContact, notes] = await Promise.all([
      fetchContact(contactId),
      fetchNotes(contactId),
    ]);
    const contact = fullContact || body.contact || { id: contactId };
    if (!contact.id) contact.id = contactId;

    const sheetRes = await logToSheet(contact, body, null, notes, contactId, null, 'sold_and_stay', true);
    console.log(`[bridge] ✅ Sold & Stay lead logged — contact ${contactId}`);
    return res.status(200).json({ success: true, sheet_status: sheetRes?.status ?? 'sent' });
  } catch (err) {
    console.error('[bridge] Fatal error (soldandstay):', err);
    return res.status(500).json({ error: err.message });
  }
}

// ─── HANDLER: STAYFRANK (stub) ───────────────────────────────────
export async function handleStayFrankSubmit(req, res) {
  if (!authorize(req, res)) return;
  const body = parseBody(req, res);
  if (!body) return;

  const contactId = extractContactId(body);
  if (!contactId) {
    return res.status(400).json({ error: 'No contactId in payload', received: Object.keys(body || {}) });
  }

  // TODO: wire payload mapping + API connection once the StayFrank spec
  // is finalized. Log the full payload so mapping can be designed later.
  console.log(`[bridge] STAYFRANK STUB — contact ${contactId}, payload:`, JSON.stringify(body)?.slice(0, 1000));
  return res.status(501).json({
    success: false,
    error: 'stayfrank_not_configured',
    message: 'StayFrank API connection is not set up yet. Payload logged for field mapping.',
  });
}

// ─── GOOGLE SHEETS LOG ───────────────────────────────────────────
async function logToSheet(contact, body, yipiPayload, notes, contactId, yipiRes, dealType, awaitIt = false) {
  const ad = yipiPayload?.application_data || {};
  const sheetsPayload = {
    first_name: contact.firstName || contact.first_name || body.first_name || '',
    last_name: contact.lastName || contact.last_name || body.last_name || '',
    email: contact.email || body.email || '',
    phone: contact.phone || body.phone || '',
    property_address: ad.property_address || contact.address1 || body.address1 || '',
    property_city: ad.property_city || contact.city || body.city || '',
    property_state: ad.property_state || contact.state || body.state || '',
    property_zip: ad.property_zip || contact.postalCode || body.postal_code || '',
    estimated_value: body['What is Your Estimate Propoerty Value'] || body['What is Your Estimated Property Value?'] || '',
    mortgage_balance: body['What is Your Mortgage Balance?'] || '',
    requested_amount: ad.requested_loan_amount || '',
    funding_reason: body['What will the funding be used for?'] || body['How Do You Plan to Repay?'] || '',
    timing: body['How Long Will You need This Funding?'] || '',
    exit_plan: '',
    deal_type: dealType || '',
    deal_notes: (notes || []).map((n) => '[' + (n.date ? new Date(n.date).toLocaleDateString('en-US') : 'No date') + ']\n' + n.body).join('\n\n'),
    notes_count: (notes || []).length,
    ghl_contact_id: contactId,
    deal_id: yipiRes?.dealId || '',
    duplicate: yipiRes?.duplicate || false,
  };

  const send = fetch(SHEETS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sheetsPayload),
  })
    .then((r) => { console.log('[bridge] Sheets write status: ' + r.status); return r; })
    .catch((e) => { console.warn('[bridge] Sheets write failed:', e.message); return null; });

  return awaitIt ? send : undefined;
}

// ─── ROUTER (used by server.js) ──────────────────────────────────
export async function route(path, req, res, query) {
  const p = (path || '/').replace(/\/+$/, '') || '/';
  if (req.method === 'GET') {
    if (p === '/yipi/deals') {
      return handleYipiDeals(req, res, query || new URLSearchParams());
    }
    return res.status(405).json({ error: 'Method not allowed' });
  }
  switch (p) {
    case '/yipi/deals':
      return handleYipiDeals(req, res, query || new URLSearchParams());
    case '/yipi/submit':
      return handleYipiSubmit(req, res, { requireDealType: true });
    case '/yipi/withdraw':
    case '/withdraw':
    case '/remove':
      return handleYipiWithdraw(req, res);
    case '/soldandstay/submit':
    case '/soldandstay':
      return handleSoldAndStaySubmit(req, res);
    case '/stayfrank/submit':
    case '/stayfrank':
      return handleStayFrankSubmit(req, res);
    default:
      // Legacy catch-all — old stage-triggered workflow posts to "/"
      return handleYipiSubmit(req, res, { requireDealType: false });
  }
}

// Backward-compat export (v1 server.js imported { handler })
export const handler = (req, res) => handleYipiSubmit(req, res, { requireDealType: false });
