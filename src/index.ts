interface Env {
  STORE: KVNamespace;
  APP_URL: string;
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_WEBHOOK_SECRET: string;
  TELEGRAM_OWNER_CHAT_ID: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  AUTH_START_KEY: string;
  TOKEN_ENCRYPTION_KEY: string;
  GMAIL_PUBSUB_TOPIC?: string;
  GMAIL_PUSH_KEY?: string;
  OPENAI_API_KEY: string;
}

type GmailToken = { access_token: string; refresh_token?: string; expires_at: number };
type GmailMessage = { id: string; threadId: string; labelIds?: string[]; snippet?: string; payload?: { mimeType?: string; filename?: string; headers?: Array<{ name: string; value: string }>; body?: { data?: string; attachmentId?: string; size?: number }; parts?: GmailMessage["payload"][] } };
type TelegramButton = { text: string; callback_data?: string; url?: string };
type TelegramKeyboard = { inline_keyboard: TelegramButton[][] };
type BotReply = { text: string; keyboard?: TelegramKeyboard };
type Flow = { type: "compose-to" | "compose-subject" | "compose-body" | "search" | "reply" | "confirm-compose" | "confirm-reply" | "label-create" | "pin-set" | "pin-unlock"; to?: string; subject?: string; messageId?: string; body?: string; pendingAction?: string };
type UiState = { messageId: number };
type PageState = { query: string; title: string; tokens: string[]; index: number; nextPageToken?: string };
type Attachment = { messageId: string; attachmentId: string; filename: string; mimeType: string; size?: number };
type ScheduledMail = { id: string; due: number; flow: Flow };
type Rules = { archive: string[]; star: string[] };
type GmailAccount = { email: string };

const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send";
const text = (value: string, max = 3800) => value.length > max ? `${value.slice(0, max - 1)}…` : value;
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]!));
const b64url = (input: string) => btoa(unescape(encodeURIComponent(input))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const header = (message: GmailMessage, name: string) => message.payload?.headers?.find(h => h.name.toLowerCase() === name.toLowerCase())?.value ?? "";

type EncryptedGmailToken = { version: 1; iv: string; ciphertext: string };

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function tokenEncryptionKey(env: Env): Promise<CryptoKey> {
  if (!/^[\da-f]{64}$/i.test(env.TOKEN_ENCRYPTION_KEY)) throw new Error("TOKEN_ENCRYPTION_KEY debe ser una clave hexadecimal de 64 caracteres");
  const rawKey = new ArrayBuffer(32);
  const bytes = new Uint8Array(rawKey);
  env.TOKEN_ENCRYPTION_KEY.match(/.{2}/g)!.forEach((pair, index) => { bytes[index] = Number.parseInt(pair, 16); });
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function isGmailToken(value: unknown): value is GmailToken {
  return typeof value === "object" && value !== null && "access_token" in value && typeof value.access_token === "string" && "expires_at" in value && typeof value.expires_at === "number";
}

function isEncryptedGmailToken(value: unknown): value is EncryptedGmailToken {
  return typeof value === "object" && value !== null && "version" in value && value.version === 1 && "iv" in value && typeof value.iv === "string" && "ciphertext" in value && typeof value.ciphertext === "string";
}

async function storeGmailToken(key: string, token: GmailToken, env: Env): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(token));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await tokenEncryptionKey(env), plaintext);
  const value: EncryptedGmailToken = { version: 1, iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
  await env.STORE.put(key, JSON.stringify(value));
}

async function readGmailToken(key: string, env: Env): Promise<GmailToken | undefined> {
  const stored = await env.STORE.get(key);
  if (!stored) return undefined;
  let value: unknown;
  try { value = JSON.parse(stored); } catch { throw new Error("El token de Gmail almacenado no es válido"); }
  if (isEncryptedGmailToken(value)) {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(decodeBase64Url(value.iv)) }, await tokenEncryptionKey(env), toArrayBuffer(decodeBase64Url(value.ciphertext)));
    const token: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    if (!isGmailToken(token)) throw new Error("El token de Gmail descifrado no es válido");
    return token;
  }
  if (!isGmailToken(value)) throw new Error("El token de Gmail almacenado no es válido");
  // Migrate existing plaintext token records the first time an account is used.
  await storeGmailToken(key, value, env);
  return value;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") return new Response(homepage, { headers: { "content-type": "text/html; charset=UTF-8" } });
    if (request.method === "GET" && url.pathname === "/privacy") return new Response(privacyPolicy, { headers: { "content-type": "text/html; charset=UTF-8" } });
    if (request.method === "GET" && url.pathname === "/auth/google") return startGoogleAuth(url, env);
    if (request.method === "GET" && url.pathname === "/auth/callback") return finishGoogleAuth(url, env);
    if (request.method === "POST" && url.pathname === "/telegram") return telegramWebhook(request, env);
    if (request.method === "POST" && url.pathname === "/gmail/push") return gmailPush(request, url, env);
    return new Response("Not found", { status: 404 });
  },
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(renewGmailWatch(env));
    ctx.waitUntil(sendDailyDigestIfDue(env));
    ctx.waitUntil(processScheduledMail(env));
    ctx.waitUntil(sendWeeklyDigestIfDue(env));
  }
};

const pageStyle = "body{margin:0;background:#f5f7fb;color:#172033;font:16px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:760px;margin:0 auto;padding:48px 24px}h1{line-height:1.2;color:#142b52}h2{margin-top:32px;color:#142b52}a{color:#155eef}header{border-bottom:1px solid #d9e0ec;background:white}header div{max-width:760px;margin:auto;padding:18px 24px;font-weight:650}footer{margin-top:48px;padding-top:18px;border-top:1px solid #d9e0ec;color:#53627a;font-size:14px}li{margin:8px 0}";
const homepage = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Asistente de correo en Telegram</title><style>${pageStyle}</style></head><body><header><div>Asistente de correo en Telegram</div></header><main><h1>Tu correo, desde tu chat privado de Telegram</h1><p>Este bot personal permite consultar y buscar mensajes de Gmail, leer correos y, cuando el usuario lo solicita, redactar, responder o programar mensajes. El bot está configurado para atender únicamente al chat de Telegram autorizado por su propietario.</p><h2>Cómo funciona</h2><p>El usuario conecta su cuenta de Google mediante OAuth. El bot consulta Gmail para realizar las acciones solicitadas y envía los resultados a la conversación privada autorizada. Algunas tareas programadas pueden procesarse periódicamente.</p><p>El bot no vende datos ni los utiliza para publicidad. Consulta la <a href="/privacy">Política de privacidad</a> para conocer qué datos se procesan, dónde se almacenan y cómo desconectar la cuenta.</p><footer>Aplicación personal. <a href="/privacy">Política de privacidad</a></footer></main></body></html>`;
const privacyPolicy = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Política de privacidad | Asistente de correo en Telegram</title><style>${pageStyle}</style></head><body><header><div><a href="/">Asistente de correo en Telegram</a></div></header><main><h1>Política de privacidad</h1><p><strong>Última actualización: 7 de octubre de 2026</strong></p><p>Esta aplicación es un bot personal de Telegram que permite a su propietario gestionar una cuenta de Gmail desde un chat privado. Esta política explica cómo se procesan los datos para prestar esas funciones.</p><h2>Datos que procesa el bot</h2><ul><li>Datos de autorización de Google y tokens OAuth necesarios para conectar Gmail.</li><li>Mensajes y metadatos de Gmail que el usuario solicita consultar, buscar, resumir o modificar.</li><li>El identificador del chat autorizado de Telegram, comandos y preferencias del bot.</li><li>El contenido de correos que el usuario decide redactar, responder o programar.</li></ul><h2>Cómo se usan y comparten</h2><p>Los datos de Gmail se usan para ejecutar las acciones solicitadas por el usuario y se devuelven al chat privado autorizado de Telegram. Google procesa las solicitudes de acceso a Gmail; Cloudflare aloja el Worker y almacena datos operativos en Cloudflare KV; Telegram transporta los comandos y respuestas.</p><p>Si el propietario habilita las funciones de inteligencia artificial, el contenido del correo seleccionado puede enviarse a OpenAI para generar un resumen, evaluar urgencia o proponer una respuesta. Si habilita la transcripción por voz, el audio enviado al bot puede enviarse a OpenAI para transcribirlo. Estas funciones no son necesarias para el uso básico del bot.</p><p>Los datos de Google no se venden, no se usan para publicidad y no se comparten con terceros salvo con los servicios anteriores cuando son necesarios para una función solicitada por el usuario.</p><h2>Almacenamiento y conservación</h2><p>Los tokens OAuth de Gmail se cifran con AES-GCM antes de almacenarse en Cloudflare KV. La clave de cifrado se guarda como secreto de Cloudflare y no en el repositorio. Las preferencias y tareas programadas necesarias para operar el bot también se almacenan en Cloudflare KV. El bot conserva esos datos mientras la cuenta esté conectada o mientras una tarea siga pendiente. El contenido de Gmail se consulta desde Google cuando se solicita y puede aparecer en las respuestas enviadas a Telegram.</p><h2>Control y eliminación</h2><p>El usuario puede usar <code>/disconnect</code> en Telegram para quitar del bot el token de la cuenta activa y detener su acceso local a Gmail. Para revocar completamente el permiso OAuth, también puede quitar el acceso de la aplicación desde la configuración de seguridad de su cuenta de Google. Las tareas programadas y preferencias del bot pueden requerir eliminación separada.</p><h2>Seguridad y contacto</h2><p>El bot restringe sus comandos al identificador de chat configurado por el propietario y utiliza servicios de infraestructura de Cloudflare, Google y Telegram. Ningún sistema conectado a Internet puede garantizar seguridad absoluta. Para consultas de privacidad, contacta al propietario del bot mediante su chat privado de Telegram.</p><footer><a href="/">Volver a la página principal</a></footer></main></body></html>`;

async function startGoogleAuth(url: URL, env: Env): Promise<Response> {
  if (url.searchParams.get("key") !== env.AUTH_START_KEY) return new Response("No autorizado", { status: 403 });
  const state = crypto.randomUUID();
  await env.STORE.put(`oauth:${state}`, "1", { expirationTtl: 600 });
  const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  auth.search = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: `${env.APP_URL}/auth/callback`, response_type: "code", scope: GMAIL_SCOPE, access_type: "offline", prompt: "consent", state }).toString();
  return Response.redirect(auth.toString(), 302);
}

async function finishGoogleAuth(url: URL, env: Env): Promise<Response> {
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (!state || !code || !await env.STORE.get(`oauth:${state}`)) return new Response("Autorización inválida o vencida.", { status: 400 });
  await env.STORE.delete(`oauth:${state}`);
  const body = new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: `${env.APP_URL}/auth/callback`, grant_type: "authorization_code" });
  const result = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  if (!result.ok) return new Response("Google rechazó la autorización. Revisa las credenciales y la URL de retorno.", { status: 400 });
  const token = await result.json() as { access_token: string; refresh_token?: string; expires_in: number };
  const profile = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/profile", { headers: { Authorization: `Bearer ${token.access_token}` } });
  if (!profile.ok) return new Response("Google autorizó el acceso, pero no pude identificar la cuenta.", { status: 400 });
  const { emailAddress } = await profile.json() as { emailAddress: string };
  const tokenKey = `gmail-token:${emailAddress}`;
  const previousToken = await readGmailToken(tokenKey, env);
  const saved: GmailToken = { access_token: token.access_token, refresh_token: token.refresh_token ?? previousToken?.refresh_token, expires_at: Date.now() + token.expires_in * 1000 };
  await storeGmailToken(tokenKey, saved, env);
  const accounts = await env.STORE.get<GmailAccount[]>("gmail-accounts", "json") ?? [];
  if (!accounts.some(account => account.email === emailAddress)) accounts.push({ email: emailAddress });
  await env.STORE.put("gmail-accounts", JSON.stringify(accounts));
  await stopGmailWatch(env);
  await env.STORE.put("active-gmail", emailAddress);
  await env.STORE.delete("gmail-watch");
  await env.STORE.delete("gmail-history");
  return new Response(`<h1>Gmail conectado</h1><p>Cuenta activa: ${escapeHtml(emailAddress)}. Ya puedes volver a Telegram.</p>`, { headers: { "content-type": "text/html; charset=UTF-8" } });
}

async function telegramWebhook(request: Request, env: Env): Promise<Response> {
  if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.TELEGRAM_WEBHOOK_SECRET) return new Response("Unauthorized", { status: 401 });
  const update = await request.json() as { message?: { message_id: number; chat: { id: number }; text?: string; voice?: { file_id: string } }; callback_query?: { id: string; data?: string; message?: { chat: { id: number }; message_id: number } } };
  const callback = update.callback_query;
  if (callback?.message && String(callback.message.chat.id) === env.TELEGRAM_OWNER_CHAT_ID) {
    let answer: BotReply;
    try { answer = await handleButton(callback.data ?? "", env); }
    catch (error) { answer = { text: `⚠️ No pude completar la acción: ${escapeHtml(error instanceof Error ? error.message : "error desconocido")}`, keyboard: await mainKeyboard(env) }; }
    await telegramAnswerCallback(env, callback.id);
    await telegramRender(env, callback.message.chat.id, answer, callback.message.message_id);
    return new Response("ok");
  }
  const msg = update.message;
  if (!msg || String(msg.chat.id) !== env.TELEGRAM_OWNER_CHAT_ID) return new Response("ok");
  if (msg.voice) {
    let answer: BotReply;
    try { answer = await handleVoice(msg.voice.file_id, env); } catch (error) { answer = { text: `⚠️ No pude transcribir la nota: ${escapeHtml(error instanceof Error ? error.message : "error desconocido")}`, keyboard: await mainKeyboard(env) }; }
    await telegramRender(env, msg.chat.id, answer);
    return new Response("ok");
  }
  if (!msg.text) return new Response("ok");
  const activeFlow = await env.STORE.get<Flow>("flow", "json");
  if (activeFlow?.type === "pin-set" || activeFlow?.type === "pin-unlock") await telegramDelete(env, msg.chat.id, msg.message_id);
  let answer: BotReply;
  try { answer = await handleText(msg.text.trim(), env); }
  catch (error) { answer = { text: `⚠️ No pude completar la acción: ${escapeHtml(error instanceof Error ? error.message : "error desconocido")}`, keyboard: await mainKeyboard(env) }; }
  await telegramRender(env, msg.chat.id, answer);
  return new Response("ok");
}

async function handleText(input: string, env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type === "pin-unlock") return continueFlow(input, flow, env);
  if (flow && !input.startsWith("/")) return continueFlow(input, flow, env);
  const [command] = input.split(/\s+/, 1);
  if (await pinRequired(`command:${command}`, env)) {
    await env.STORE.put("flow", JSON.stringify({ type: "pin-unlock", pendingAction: `command:${input}` } satisfies Flow), { expirationTtl: 300 });
    return { text: "🔐 Escribe tu PIN para continuar. Quedará desbloqueado durante 15 minutos.", keyboard: cancelKeyboard() };
  }
  if (command === "/inbox") {
    const messages = await getMessageList("in:inbox", Number(input.slice(command.length).trim()) || 8, env);
    return { text: formatMessageList(messages, "📬 Correos"), keyboard: messageKeyboard(messages) };
  }
  if (command === "/search") {
    const query = input.slice(command.length).trim();
    if (!query) return { text: "Uso: /search consulta", keyboard: await mainKeyboard(env) };
    const messages = await getMessageList(query, 8, env);
    return { text: formatMessageList(messages, "🔎 Resultados"), keyboard: messageKeyboard(messages) };
  }
  if (command === "/read") {
    const id = input.slice(command.length).trim();
    if (!id) return { text: "Uso: /read ID", keyboard: await mainKeyboard(env) };
    return { text: escapeHtml(await readMessage(id, env)), keyboard: await readKeyboard(id, env) };
  }
  if (command === "/send") return prepareDirectSend(input.slice(command.length).trim(), env);
  if (command === "/reply") return prepareDirectReply(input.slice(command.length).trim(), env);
  const textReply = await handleCommand(input, env);
  if (input === "/start" || input === "/help") return { text: "✨ <b>Bienvenido a Gmail en Telegram</b>\nElige una acción:", keyboard: await mainKeyboard(env) };
  return { text: escapeHtml(textReply), keyboard: await mainKeyboard(env) };
}

async function handleCommand(input: string, env: Env): Promise<string> {
  const [command] = input.split(/\s+/, 1);
  const rest = input.slice(command.length).trim();
  if (command === "/start" || command === "/help") return "✨ Menú principal";
  if (command === "/connect") return `Abre este enlace privado para conectar Gmail:\n${env.APP_URL}/auth/google?key=${env.AUTH_START_KEY}`;
  if (command === "/disconnect") { await disconnectActiveAccount(env); return "Acceso de la cuenta activa eliminado del bot."; }
  return "No conozco ese comando. Usa /help.";
}

async function prepareDirectSend(input: string, env: Env): Promise<BotReply> {
  const [to, subject, ...bodyParts] = input.split("|").map(value => value.trim());
  const body = bodyParts.join("|");
  if (!to || !subject || !body) return { text: "Uso: /send destinatario | asunto | mensaje", keyboard: await mainKeyboard(env) };
  if (body.length > 3000) return { text: "El mensaje supera el límite de 3000 caracteres para poder revisarlo completo aquí. Divídelo en varios correos.", keyboard: await mainKeyboard(env) };
  await env.STORE.put("flow", JSON.stringify({ type: "confirm-compose", to, subject, body } satisfies Flow), { expirationTtl: 600 });
  return { text: `📨 <b>Revisa antes de enviar</b>\n\n<b>Para:</b> ${escapeHtml(to)}\n<b>Asunto:</b> ${escapeHtml(subject)}\n\n${escapeHtml(body)}`, keyboard: confirmKeyboard() };
}

async function prepareDirectReply(input: string, env: Env): Promise<BotReply> {
  const [id, ...bodyParts] = input.split("|").map(value => value.trim());
  const body = bodyParts.join("|");
  if (!id || !body) return { text: "Uso: /reply ID | mensaje", keyboard: await mainKeyboard(env) };
  if (body.length > 3000) return { text: "La respuesta supera el límite de 3000 caracteres para poder revisarla completa aquí. Divídela en varios mensajes.", keyboard: await mainKeyboard(env) };
  const original = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=metadata&metadataHeaders=From&metadataHeaders=Reply-To&metadataHeaders=Subject`, env)).json() as GmailMessage;
  const to = header(original, "Reply-To") || header(original, "From");
  await env.STORE.put("flow", JSON.stringify({ type: "confirm-reply", messageId: id, body } satisfies Flow), { expirationTtl: 600 });
  return { text: `↩️ <b>Revisa la respuesta</b>\n\n<b>Para:</b> ${escapeHtml(to)}\n<b>Asunto:</b> ${escapeHtml(header(original, "Subject"))}\n\n${escapeHtml(body)}`, keyboard: confirmKeyboard() };
}

async function handleButton(data: string, env: Env): Promise<BotReply> {
  if (await pinRequired(data, env)) { await env.STORE.put("flow", JSON.stringify({ type: "pin-unlock", pendingAction: data } satisfies Flow), { expirationTtl: 300 }); return { text: "🔐 Escribe tu PIN para continuar. Quedará desbloqueado durante 15 minutos.", keyboard: cancelKeyboard() }; }
  if (data === "menu:home") return { text: "🏠 <b>Menú principal</b>\n¿Qué quieres hacer?", keyboard: await mainKeyboard(env) };
  if (data === "menu:inbox") return renderPage("inbox", "in:inbox", "📬 Bandeja de entrada", env);
  if (data === "menu:unread") return renderPage("unread", "is:unread", "🔴 No leídos", env);
  if (data === "menu:starred") return renderPage("starred", "is:starred", "⭐ Destacados", env);
  if (data === "menu:today") return renderPage("today", "newer_than:1d", "🗓️ Recibidos hoy", env);
  if (data === "menu:sent") return renderPage("sent", "in:sent", "📤 Correos enviados", env);
  if (data === "menu:trash") return renderPage("trash", "in:trash", "🗑️ Papelera", env);
  if (data === "menu:spam") return renderPage("spam", "in:spam", "🚫 Spam", env);
  if (data === "menu:filters") return { text: "🔎 <b>Filtros rápidos</b>", keyboard: { inline_keyboard: [[{ text: "📎 Con adjuntos", callback_data: "filter:attachments" }, { text: "🗓️ Última semana", callback_data: "filter:week" }], [{ text: "🧾 Facturas y pagos", callback_data: "filter:invoices" }], [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
  if (data === "filter:attachments") return renderPage("attachments", "has:attachment", "📎 Correos con adjuntos", env);
  if (data === "filter:week") return renderPage("week", "newer_than:7d", "🗓️ Últimos 7 días", env);
  if (data === "filter:invoices") return renderPage("invoices", "(factura OR invoice OR pago OR payment OR recibo OR receipt)", "🧾 Facturas y pagos", env);
  if (data.startsWith("page:")) { const [, key, direction] = data.split(":"); return renderPage(key, "", "", env, direction); }
  if (data === "flow:search") { await env.STORE.put("flow", JSON.stringify({ type: "search" } satisfies Flow), { expirationTtl: 600 }); return { text: "🔎 <b>Buscar correo</b>\nEscribe lo que deseas buscar. Ejemplo: <code>from:cliente@example.com</code> o <code>factura</code>", keyboard: cancelKeyboard() }; }
  if (data === "flow:compose") { await env.STORE.put("flow", JSON.stringify({ type: "compose-to" } satisfies Flow), { expirationTtl: 600 }); return { text: "✉️ <b>Nuevo correo</b>\nEscribe el correo del destinatario:", keyboard: cancelKeyboard() }; }
  if (data.startsWith("mail:read:")) return { text: escapeHtml(await readMessage(data.slice(10), env)), keyboard: await readKeyboard(data.slice(10), env) };
  if (data.startsWith("ai:menu:")) return aiMenu(data.slice(8));
  if (data.startsWith("ai:summary:")) return aiReadAction("summary", data.slice(11), env);
  if (data.startsWith("ai:urgency:")) return aiReadAction("urgency", data.slice(11), env);
  if (data.startsWith("ai:reply:")) return aiReadAction("reply", data.slice(9), env);
  if (data.startsWith("mail:thread:")) return threadView(data.slice(12), env);
  if (data.startsWith("mail:labels:")) return labelMenu(data.slice(12), env);
  if (data.startsWith("label:add:")) return addLabelToMessage(data, env);
  if (data.startsWith("label:create:")) { await env.STORE.put("flow", JSON.stringify({ type: "label-create", messageId: data.slice(13) } satisfies Flow), { expirationTtl: 600 }); return { text: "🏷️ Escribe el nombre de la nueva etiqueta:", keyboard: cancelKeyboard() }; }
  if (data.startsWith("mail:trash-confirm:")) { await messageAction("trash", data.slice(19), env); return { text: "🗑️ Correo enviado a la papelera.", keyboard: await mainKeyboard(env) }; }
  if (data.startsWith("mail:attachments:")) return attachmentMenu(data.slice(17), env);
  if (data.startsWith("mail:attachment:")) { await sendAttachment(Number(data.slice(16)), env); return { text: "📎 <b>Archivo enviado</b>", keyboard: await mainKeyboard(env) }; }
  if (data.startsWith("templates:for:")) return templateMenu(data.slice(14));
  if (data.startsWith("template:")) return chooseTemplate(data, env);
  if (data === "templates:menu") return { text: "💬 <b>Respuestas rápidas</b>\nAbre un correo y pulsa <b>Plantillas</b> para responder con un texto preparado.", keyboard: await mainKeyboard(env) };
  if (data === "menu:drafts") return listDrafts(env);
  if (data.startsWith("draft:open:")) return openDraft(data.slice(11), env);
  if (data.startsWith("draft:send:")) { await sendDraft(data.slice(11), env); return { text: "✅ <b>Borrador enviado</b>", keyboard: await mainKeyboard(env) }; }
  if (data.startsWith("draft:delete:")) { await gmailFetch(`drafts/${encodeURIComponent(data.slice(13))}`, env, { method: "DELETE" }); return { text: "🗑️ Borrador eliminado.", keyboard: await mainKeyboard(env) }; }
  if (data === "save:draft") return saveDraft(env);
  if (data === "send:edit") return editPendingSend(env);
  if (data === "schedule:menu") return scheduleMenu(env);
  if (data === "schedule:hour") return scheduleMail(60 * 60 * 1000, "en una hora", env);
  if (data === "schedule:tomorrow") return scheduleMail(24 * 60 * 60 * 1000, "mañana a esta hora", env);
  if (data === "menu:scheduled") return listScheduledMail(env);
  if (data.startsWith("schedule:cancel:")) return cancelScheduledMail(data.slice(16), env);
  if (data === "menu:contacts") return listContacts(env);
  if (data.startsWith("contact:to:")) return chooseContact(Number(data.slice(11)), env);
  if (data === "menu:history") return listHistory(env);
  if (data === "menu:dashboard") return dashboard(env);
  if (data === "pin:setup") { await env.STORE.put("flow", JSON.stringify({ type: "pin-set" } satisfies Flow), { expirationTtl: 300 }); return { text: "🔐 Escribe un PIN numérico de 4 a 8 dígitos. No lo envíes por capturas.", keyboard: cancelKeyboard() }; }
  if (data === "pin:disable") { await env.STORE.delete("pin-hash"); await env.STORE.delete("pin-valid-until"); return { text: "🔓 PIN desactivado.", keyboard: await mainKeyboard(env) }; }
  if (data === "alerts:menu") return alertPauseMenu(env);
  if (data.startsWith("alerts:mute:")) return muteAlerts(Number(data.slice(12)), env);
  if (data === "alerts:unmute") { await env.STORE.delete("alerts-muted-until"); return { text: "🔔 Alertas reactivadas.", keyboard: await mainKeyboard(env) }; }
  if (data === "menu:cleanup") return { text: "🧹 <b>Limpiar promociones</b>\nArchivará hasta 30 correos de la categoría Promociones que estén en la bandeja. ¿Continuar?", keyboard: { inline_keyboard: [[{ text: "🧹 Archivar promociones", callback_data: "cleanup:promotions" }], [{ text: "↩️ Cancelar", callback_data: "menu:home" }]] } };
  if (data === "cleanup:promotions") return cleanupPromotions(env);
  if (data.startsWith("rule:menu:")) return ruleMenu(data.slice(10));
  if (data.startsWith("rule:archive:")) return addRule("archive", data.slice(13), env);
  if (data.startsWith("rule:star:")) return addRule("star", data.slice(10), env);
  if (data.startsWith("vip:add:")) return addVip(data.slice(8), env);
  if (data === "vip:list") return listVip(env);
  if (data.startsWith("vip:remove:")) return removeVip(Number(data.slice(11)), env);
  if (data.startsWith("mail:action:")) {
    const [, , action, id] = data.split(":");
    if (!id) return { text: "⚠️ No encontré el correo seleccionado.", keyboard: await mainKeyboard(env) };
    if (action === "trash") return { text: "⚠️ <b>¿Enviar este correo a la papelera?</b>", keyboard: { inline_keyboard: [[{ text: "🗑️ Sí, eliminar", callback_data: `mail:trash-confirm:${id}` }, { text: "↩️ Cancelar", callback_data: `mail:read:${id}` }]] } };
    await messageAction(action, id, env);
    const labels: Record<string, string> = { read: "✅ Marcado como leído", unread: "🔴 Marcado como no leído", star: "⭐ Correo destacado", archive: "📦 Correo archivado", trash: "🗑️ Correo enviado a la papelera", restore: "♻️ Correo recuperado", unspam: "✅ Correo recuperado de spam" };
    return { text: labels[action] ?? "✅ Acción realizada", keyboard: await mainKeyboard(env) };
  }
  if (data.startsWith("flow:reply:")) { const id = data.slice(11); await env.STORE.put("flow", JSON.stringify({ type: "reply", messageId: id } satisfies Flow), { expirationTtl: 600 }); return { text: "↩️ <b>Responder</b>\nEscribe tu respuesta y la enviaré al correo original.", keyboard: cancelKeyboard() }; }
  if (data === "send:confirm") return confirmSend(env);
  if (data === "send:cancel") { await env.STORE.delete("flow"); return { text: "✖️ Envío cancelado. No se mandó ningún correo.", keyboard: await mainKeyboard(env) }; }
  if (data === "account:status") { const active = await activeAccount(env); return { text: active ? `✅ <b>Gmail conectado</b>\nCuenta activa: <b>${escapeHtml(active.email)}</b>` : "⚠️ <b>Gmail no está conectado</b>\nUsa el botón Conectar Gmail.", keyboard: await mainKeyboard(env) }; }
  if (data === "account:switch") return accountMenu(env);
  if (data.startsWith("account:use:")) { await stopGmailWatch(env); await env.STORE.put("active-gmail", data.slice(12)); await env.STORE.delete("gmail-watch"); await env.STORE.delete("gmail-history"); return { text: `✅ Cuenta activa: <b>${escapeHtml(data.slice(12) === "legacy" ? "Cuenta original" : data.slice(12))}</b>\nPulsa 🔔 Activar avisos si quieres alertas para esta cuenta.`, keyboard: await mainKeyboard(env) }; }
  if (data === "notifications:enable") return enableNotifications(env);
  if (data === "notifications:mode") return toggleNotificationMode(env);
  if (data === "account:disconnect") { await disconnectActiveAccount(env); await env.STORE.delete("flow"); return { text: "🗑️ Acceso de la cuenta activa eliminado.", keyboard: await mainKeyboard(env) }; }
  if (data === "flow:cancel") { await env.STORE.delete("flow"); return { text: "✖️ Acción cancelada.", keyboard: await mainKeyboard(env) }; }
  return { text: "No reconocí esa acción.", keyboard: await mainKeyboard(env) };
}

async function continueFlow(input: string, flow: Flow, env: Env): Promise<BotReply> {
  if (flow.type === "pin-set") {
    if (!/^\d{4,8}$/.test(input)) return { text: "⚠️ El PIN debe tener entre 4 y 8 números.", keyboard: cancelKeyboard() };
    await env.STORE.put("pin-hash", await hashPin(input)); await env.STORE.delete("flow");
    return { text: "🔐 PIN configurado. Se pedirá antes de leer, enviar o eliminar correos.", keyboard: await mainKeyboard(env) };
  }
  if (flow.type === "pin-unlock") {
    if (await env.STORE.get("pin-hash") !== await hashPin(input)) return { text: "⚠️ PIN incorrecto. Inténtalo otra vez.", keyboard: cancelKeyboard() };
    await env.STORE.put("pin-valid-until", String(Date.now() + 15 * 60 * 1000)); await env.STORE.delete("flow");
    if (flow.pendingAction?.startsWith("command:")) return handleText(flow.pendingAction.slice("command:".length), env);
    return handleButton(flow.pendingAction ?? "menu:home", env);
  }
  if (flow.type === "search") {
    await env.STORE.delete("flow"); const messages = await getMessageList(input, 8, env);
    return { text: formatMessageList(messages, "🔎 Resultados"), keyboard: messageKeyboard(messages) };
  }
  if (flow.type === "label-create" && flow.messageId) {
    const created = await (await gmailFetch("labels", env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: input, labelListVisibility: "labelShow", messageListVisibility: "show" }) })).json() as { id: string; name: string };
    await messageActionWithLabel(flow.messageId, created.id, env);
    await env.STORE.delete("flow");
    return { text: `🏷️ Etiqueta <b>${escapeHtml(created.name)}</b> creada y aplicada.`, keyboard: await readKeyboard(flow.messageId, env) };
  }
  if (flow.type === "compose-to") { await env.STORE.put("flow", JSON.stringify({ type: "compose-subject", to: input } satisfies Flow), { expirationTtl: 600 }); return { text: "📝 Ahora escribe el <b>asunto</b> del correo:", keyboard: cancelKeyboard() }; }
  if (flow.type === "compose-subject") { await env.STORE.put("flow", JSON.stringify({ type: "compose-body", to: flow.to, subject: input } satisfies Flow), { expirationTtl: 600 }); return { text: "💬 Escribe el <b>mensaje</b> que quieres enviar:", keyboard: cancelKeyboard() }; }
  if (flow.type === "compose-body") {
    if (input.length > 3000) return { text: "El mensaje supera el límite de 3000 caracteres para poder revisarlo completo aquí. Divídelo en varios correos.", keyboard: cancelKeyboard() };
    await env.STORE.put("flow", JSON.stringify({ type: "confirm-compose", to: flow.to, subject: flow.subject, body: input } satisfies Flow), { expirationTtl: 600 });
    return { text: `📨 <b>Revisa antes de enviar</b>\n\n<b>Para:</b> ${escapeHtml(flow.to ?? "")}\n<b>Asunto:</b> ${escapeHtml(flow.subject ?? "")}\n\n${escapeHtml(input)}`, keyboard: confirmKeyboard() };
  }
  if (flow.type === "reply" && flow.messageId) {
    if (input.length > 3000) return { text: "La respuesta supera el límite de 3000 caracteres para poder revisarla completa aquí. Divídela en varios mensajes.", keyboard: cancelKeyboard() };
    await env.STORE.put("flow", JSON.stringify({ type: "confirm-reply", messageId: flow.messageId, body: input } satisfies Flow), { expirationTtl: 600 });
    return { text: `↩️ <b>Revisa la respuesta</b>\n\n${escapeHtml(input)}`, keyboard: confirmKeyboard() };
  }
  await env.STORE.delete("flow"); return { text: "⚠️ La acción venció. Inténtalo de nuevo.", keyboard: await mainKeyboard(env) };
}

async function hashPin(pin: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`gmail-telegram-pin:${pin}`)));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

async function pinRequired(data: string, env: Env): Promise<boolean> {
  if (!await env.STORE.get("pin-hash")) return false;
  if (Number(await env.STORE.get("pin-valid-until") ?? 0) > Date.now()) return false;
  if (data.startsWith("command:")) return ["/inbox", "/search", "/read", "/send", "/reply"].includes(data.slice("command:".length).split(/\s+/, 1)[0]);
  return data === "menu:inbox" || data === "menu:unread" || data === "menu:starred" || data === "menu:today" || data === "menu:sent" || data === "menu:trash" || data === "menu:spam" || data === "menu:drafts" || data === "menu:contacts" || data === "menu:history" || data === "menu:scheduled" || data.startsWith("filter:") || data.startsWith("mail:read:") || data.startsWith("mail:thread:") || data.startsWith("mail:attachment:") || data.startsWith("ai:") || data === "send:confirm" || data.startsWith("draft:open:") || data.startsWith("draft:send:") || data.startsWith("draft:delete:") || data.startsWith("mail:trash-confirm:") || data.startsWith("schedule:") || data === "pin:disable";
}

async function confirmSend(env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type === "confirm-compose" && flow.to && flow.subject && flow.body) {
    await sendRaw(`To: ${flow.to}\r\nSubject: ${flow.subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${flow.body}`, env);
    await rememberContacts(flow.to, env);
    await env.STORE.delete("flow"); return { text: "✅ <b>Correo enviado</b>", keyboard: await mainKeyboard(env) };
  }
  if (flow?.type === "confirm-reply" && flow.messageId && flow.body) {
    await reply(`${flow.messageId} | ${flow.body}`, env);
    await env.STORE.delete("flow"); return { text: "✅ <b>Respuesta enviada</b>", keyboard: await mainKeyboard(env) };
  }
  return { text: "⚠️ El borrador venció. Redacta el correo otra vez.", keyboard: await mainKeyboard(env) };
}

async function mainKeyboard(env: Env): Promise<TelegramKeyboard> {
  const active = await activeAccount(env);
  const connected = Boolean(active?.token);
  const watchEnabled = Boolean(await env.STORE.get("gmail-watch"));
  const notificationMode = await env.STORE.get("notification-mode") || "smart";
  const rows: TelegramButton[][] = [
    [{ text: "📬 Bandeja", callback_data: "menu:inbox" }, { text: "🔴 No leídos", callback_data: "menu:unread" }],
    [{ text: "🔎 Buscar", callback_data: "flow:search" }, { text: "⚡ Filtros", callback_data: "menu:filters" }, { text: "✉️ Redactar", callback_data: "flow:compose" }],
    [{ text: "⭐ Destacados", callback_data: "menu:starred" }, { text: "🗓️ Hoy", callback_data: "menu:today" }],
    [{ text: "📤 Enviados", callback_data: "menu:sent" }, { text: "🗑️ Papelera", callback_data: "menu:trash" }, { text: "🚫 Spam", callback_data: "menu:spam" }],
    [{ text: "🗂️ Borradores", callback_data: "menu:drafts" }, { text: "👑 Contactos VIP", callback_data: "vip:list" }],
    [{ text: "👥 Contactos", callback_data: "menu:contacts" }, { text: "📜 Actividad", callback_data: "menu:history" }],
    [{ text: "📊 Panel", callback_data: "menu:dashboard" }, { text: "🔕 Alertas", callback_data: "alerts:menu" }, { text: "🧹 Limpiar", callback_data: "menu:cleanup" }],
    [{ text: `📧 ${active?.email ?? "Cuenta Gmail"}`, callback_data: "account:switch" }],
    [{ text: await env.STORE.get("pin-hash") ? "🔐 PIN activo" : "🔐 Configurar PIN", callback_data: await env.STORE.get("pin-hash") ? "pin:disable" : "pin:setup" }],
    [{ text: "⏰ Envíos programados", callback_data: "menu:scheduled" }],
    [{ text: watchEnabled ? `🔔 Avisos: ${notificationMode === "smart" ? "inteligentes" : "todos"}` : "🔔 Activar avisos", callback_data: watchEnabled ? "notifications:mode" : "notifications:enable" }, { text: "💬 Plantillas", callback_data: "templates:menu" }],
    [{ text: "⚙️ Estado", callback_data: "account:status" }]
  ];
  if (connected) rows.push([{ text: "🗑️ Desconectar Gmail", callback_data: "account:disconnect" }]);
  else rows.push([{ text: "🔗 Conectar Gmail", url: `${env.APP_URL}/auth/google?key=${env.AUTH_START_KEY}` }]);
  return { inline_keyboard: rows };
}

const cancelKeyboard = (): TelegramKeyboard => ({ inline_keyboard: [[{ text: "✖️ Cancelar", callback_data: "flow:cancel" }], [{ text: "🏠 Menú", callback_data: "menu:home" }]] });
const confirmKeyboard = (): TelegramKeyboard => ({ inline_keyboard: [[{ text: "✅ Enviar ahora", callback_data: "send:confirm" }, { text: "⏰ Programar", callback_data: "schedule:menu" }], [{ text: "💾 Guardar borrador", callback_data: "save:draft" }, { text: "✍️ Editar", callback_data: "send:edit" }], [{ text: "✖️ Cancelar", callback_data: "send:cancel" }]] });
async function readKeyboard(id: string, env: Env): Promise<TelegramKeyboard> {
  const message = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=metadata`, env)).json() as GmailMessage;
  const labels = new Set(message.labelIds ?? []);
  const isTrash = labels.has("TRASH");
  const isSpam = labels.has("SPAM");
  const rows: TelegramButton[][] = [
    [{ text: "↩️ Responder", callback_data: `flow:reply:${id}` }, { text: "💬 Plantillas", callback_data: `templates:for:${id}` }],
    [{ text: "👑 Marcar VIP", callback_data: `vip:add:${id}` }, { text: "⚙️ Crear regla", callback_data: `rule:menu:${id}` }],
    [{ text: "🤖 IA", callback_data: `ai:menu:${id}` }, { text: "📎 Adjuntos", callback_data: `mail:attachments:${id}` }],
    [{ text: "🧵 Ver conversación", callback_data: `mail:thread:${id}` }, { text: "🏷️ Etiquetas", callback_data: `mail:labels:${id}` }],
  ];
  if (!isTrash && !isSpam) {
    rows.push([{ text: labels.has("UNREAD") ? "📥 Marcar leído" : "🔴 Marcar no leído", callback_data: `mail:action:${labels.has("UNREAD") ? "read" : "unread"}:${id}` }]);
    rows.push([{ text: "⭐ Destacar", callback_data: `mail:action:star:${id}` }, ...(labels.has("INBOX") ? [{ text: "📦 Archivar", callback_data: `mail:action:archive:${id}` }] : [])]);
    rows.push([{ text: "🗑️ Eliminar", callback_data: `mail:action:trash:${id}` }]);
  } else if (isTrash) {
    rows.push([{ text: "♻️ Recuperar de papelera", callback_data: `mail:action:restore:${id}` }]);
  } else {
    rows.push([{ text: "✅ No es spam", callback_data: `mail:action:unspam:${id}` }]);
  }
  rows.push([{ text: "📬 Bandeja", callback_data: "menu:inbox" }, { text: "🏠 Menú", callback_data: "menu:home" }]);
  return { inline_keyboard: rows };
}
const messageKeyboard = (messages: GmailMessage[], page?: { key: string; hasPrev: boolean; hasNext: boolean }): TelegramKeyboard => ({ inline_keyboard: [
  ...messages.map((m, index) => [{ text: `📨 ${index + 1}. ${(header(m, "Subject") || "Sin asunto").slice(0, 35)}`, callback_data: `mail:read:${m.id}` }]),
  ...(page && (page.hasPrev || page.hasNext) ? [[...(page.hasPrev ? [{ text: "⬅️ Anterior", callback_data: `page:${page.key}:prev` }] : []), ...(page.hasNext ? [{ text: "Siguiente ➡️", callback_data: `page:${page.key}:next` }] : [])]] : []),
  [{ text: "🏠 Menú", callback_data: "menu:home" }]
] });

async function activeAccount(env: Env): Promise<{ email: string; key: string; token: GmailToken } | undefined> {
  const email = await env.STORE.get("active-gmail");
  if (email && email !== "legacy") { const key = `gmail-token:${email}`; const token = await readGmailToken(key, env); if (token) return { email, key, token }; }
  const legacy = await readGmailToken("gmail-token", env);
  return legacy ? { email: "Cuenta original", key: "gmail-token", token: legacy } : undefined;
}

async function disconnectActiveAccount(env: Env): Promise<void> {
  const active = await activeAccount(env);
  if (!active) return;
  await env.STORE.delete(active.key);
  const accounts = (await env.STORE.get<GmailAccount[]>("gmail-accounts", "json") ?? []).filter(account => account.email !== active.email);
  await env.STORE.put("gmail-accounts", JSON.stringify(accounts));
  await env.STORE.delete("active-gmail");
  if (accounts[0]) await env.STORE.put("active-gmail", accounts[0].email);
}

async function accountMenu(env: Env): Promise<BotReply> {
  const accounts = await env.STORE.get<GmailAccount[]>("gmail-accounts", "json") ?? [];
  const legacy = Boolean(await env.STORE.get("gmail-token"));
  const rows: TelegramButton[][] = accounts.map(account => [{ text: `📧 ${account.email}`, callback_data: `account:use:${account.email}` }]);
  if (legacy) rows.push([{ text: "📧 Cuenta original", callback_data: "account:use:legacy" }]);
  rows.push([{ text: "➕ Conectar otro Gmail", url: `${env.APP_URL}/auth/google?key=${env.AUTH_START_KEY}` }], [{ text: "🏠 Menú", callback_data: "menu:home" }]);
  return { text: "📧 <b>Cuentas Gmail</b>\nElige la cuenta con la que quieres trabajar:", keyboard: { inline_keyboard: rows } };
}

async function gmailFetch(path: string, env: Env, init: RequestInit = {}): Promise<Response> {
  const active = await activeAccount(env);
  let token = active?.token;
  if (!active || !token) throw new Error("primero usa /connect");
  if (token.expires_at < Date.now() + 30_000) {
    if (!token.refresh_token) throw new Error("vuelve a conectar Gmail");
    const body = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: token.refresh_token, grant_type: "refresh_token" });
    const refreshed = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    if (!refreshed.ok) throw new Error("Google pidió volver a autorizar la cuenta");
    const data = await refreshed.json() as { access_token: string; expires_in: number };
    token = { ...token, access_token: data.access_token, expires_at: Date.now() + data.expires_in * 1000 };
    await storeGmailToken(active.key, token, env);
  }
  const headers = new Headers(init.headers); headers.set("Authorization", `Bearer ${token.access_token}`);
  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/${path}`, { ...init, headers });
  if (!response.ok) throw new Error(`Gmail respondió ${response.status}`);
  return response;
}

async function enableNotifications(env: Env): Promise<BotReply> {
  if (!env.GMAIL_PUBSUB_TOPIC || !env.GMAIL_PUSH_KEY) return { text: "⚠️ Las notificaciones aún no están configuradas en Google Cloud.", keyboard: await mainKeyboard(env) };
  const response = await gmailFetch("watch", env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ topicName: env.GMAIL_PUBSUB_TOPIC, labelIds: ["INBOX"], labelFilterBehavior: "INCLUDE" }) });
  const watch = await response.json() as { expiration?: string; historyId?: string };
  await env.STORE.put("gmail-watch", JSON.stringify(watch));
  if (watch.historyId) await env.STORE.put("gmail-history", watch.historyId);
  const expires = watch.expiration ? new Date(Number(watch.expiration)).toLocaleDateString("es-PE") : "próximamente";
  return { text: `🔔 <b>Notificaciones activadas</b>\nTe avisaré cuando haya actividad nueva en la bandeja. La suscripción se renueva antes del ${expires}.`, keyboard: await mainKeyboard(env) };
}

// Gmail only permits one active watch per user.  Before selecting or authorizing
// another account, stop the current watch so alerts cannot arrive crossed.
async function stopGmailWatch(env: Env): Promise<void> {
  if (!await env.STORE.get("gmail-watch")) return;
  try {
    await gmailFetch("stop", env, { method: "POST" });
  } catch {
    // The watch may already have expired or Google may have revoked it.
  }
  await env.STORE.delete("gmail-watch");
  await env.STORE.delete("gmail-history");
}

async function toggleNotificationMode(env: Env): Promise<BotReply> {
  const current = await env.STORE.get("notification-mode") || "smart";
  const next = current === "smart" ? "all" : "smart";
  await env.STORE.put("notification-mode", next);
  return { text: next === "smart" ? "🧠 <b>Avisos inteligentes activados</b>\nSolo te avisaré de correos marcados importantes o con asuntos de seguridad, pagos, facturas y urgencias." : "🔔 <b>Todos los avisos activados</b>\nRecibirás un aviso por cada correo nuevo.", keyboard: await mainKeyboard(env) };
}

function templateMenu(id: string): BotReply {
  return {
    text: "💬 <b>Elige una respuesta rápida</b>",
    keyboard: { inline_keyboard: [
      [{ text: "✅ Recibido, gracias", callback_data: `template:received:${id}` }],
      [{ text: "🕒 Lo reviso y respondo pronto", callback_data: `template:review:${id}` }],
      [{ text: "📅 Coordinemos una llamada", callback_data: `template:meeting:${id}` }],
      [{ text: "✍️ Escribir respuesta propia", callback_data: `flow:reply:${id}` }],
      [{ text: "↩️ Volver", callback_data: `mail:read:${id}` }]
    ] }
  };
}

async function chooseTemplate(data: string, env: Env): Promise<BotReply> {
  const [, key, id] = data.split(":");
  const templates: Record<string, string> = {
    received: "Hola,\n\nRecibido, muchas gracias. Lo revisaré y te responderé a la brevedad.\n\nSaludos.",
    review: "Hola,\n\nGracias por tu mensaje. Lo estoy revisando y te responderé pronto.\n\nSaludos.",
    meeting: "Hola,\n\nGracias por tu mensaje. ¿Te parece si coordinamos una llamada para revisarlo?\n\nSaludos."
  };
  const body = templates[key];
  if (!body || !id) return { text: "⚠️ La plantilla ya no está disponible.", keyboard: await mainKeyboard(env) };
  await env.STORE.put("flow", JSON.stringify({ type: "confirm-reply", messageId: id, body } satisfies Flow), { expirationTtl: 600 });
  return { text: `📨 <b>Revisa antes de enviar</b>\n\n${escapeHtml(body)}`, keyboard: confirmKeyboard() };
}

async function editPendingSend(env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type === "confirm-compose") { await env.STORE.put("flow", JSON.stringify({ type: "compose-body", to: flow.to, subject: flow.subject } satisfies Flow), { expirationTtl: 600 }); return { text: "✍️ Escribe nuevamente el mensaje completo:", keyboard: cancelKeyboard() }; }
  if (flow?.type === "confirm-reply") { await env.STORE.put("flow", JSON.stringify({ type: "reply", messageId: flow.messageId } satisfies Flow), { expirationTtl: 600 }); return { text: "✍️ Escribe nuevamente tu respuesta completa:", keyboard: cancelKeyboard() }; }
  return { text: "⚠️ El borrador venció.", keyboard: await mainKeyboard(env) };
}

async function scheduleMenu(env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type !== "confirm-compose" && flow?.type !== "confirm-reply") return { text: "⚠️ Primero redacta un correo para programarlo.", keyboard: await mainKeyboard(env) };
  return { text: "⏰ <b>¿Cuándo quieres enviarlo?</b>", keyboard: { inline_keyboard: [[{ text: "🕐 En una hora", callback_data: "schedule:hour" }, { text: "🌅 Mañana, misma hora", callback_data: "schedule:tomorrow" }], [{ text: "✖️ Cancelar", callback_data: "send:cancel" }]] } };
}

async function scheduleMail(delay: number, label: string, env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type !== "confirm-compose" && flow?.type !== "confirm-reply") return { text: "⚠️ El correo ya no está disponible.", keyboard: await mainKeyboard(env) };
  const scheduled = await env.STORE.get<ScheduledMail[]>("scheduled-mail", "json") ?? [];
  scheduled.push({ id: crypto.randomUUID().slice(0, 8), due: Date.now() + delay, flow });
  await env.STORE.put("scheduled-mail", JSON.stringify(scheduled));
  await env.STORE.delete("flow");
  return { text: `⏰ <b>Correo programado</b>\nSe enviará ${label}.`, keyboard: await mainKeyboard(env) };
}

async function listScheduledMail(env: Env): Promise<BotReply> {
  const scheduled = await env.STORE.get<ScheduledMail[]>("scheduled-mail", "json") ?? [];
  if (!scheduled.length) return { text: "⏰ No tienes correos programados.", keyboard: await mainKeyboard(env) };
  return { text: "⏰ <b>Envíos programados</b>", keyboard: { inline_keyboard: [...scheduled.map(mail => [{ text: `✖️ ${new Date(mail.due).toLocaleString("es-PE", { timeZone: "America/Santiago" })}`, callback_data: `schedule:cancel:${mail.id}` }]), [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
}

async function cancelScheduledMail(id: string, env: Env): Promise<BotReply> {
  const scheduled = await env.STORE.get<ScheduledMail[]>("scheduled-mail", "json") ?? [];
  await env.STORE.put("scheduled-mail", JSON.stringify(scheduled.filter(mail => mail.id !== id)));
  return { text: "✖️ Envío programado cancelado.", keyboard: await mainKeyboard(env) };
}

async function createDraft(raw: string, env: Env, threadId?: string): Promise<void> {
  validateOutgoingRaw(raw);
  await gmailFetch("drafts", env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: { raw: b64url(raw), ...(threadId ? { threadId } : {}) } }) });
}

async function saveDraft(env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type === "confirm-compose" && flow.to && flow.subject && flow.body) {
    await createDraft(`To: ${flow.to}\r\nSubject: ${flow.subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${flow.body}`, env);
  } else if (flow?.type === "confirm-reply" && flow.messageId && flow.body) {
    const original = await (await gmailFetch(`messages/${encodeURIComponent(flow.messageId)}?format=metadata&metadataHeaders=From&metadataHeaders=Reply-To&metadataHeaders=Subject&metadataHeaders=Message-ID`, env)).json() as GmailMessage;
    const to = header(original, "Reply-To") || header(original, "From"); const messageId = header(original, "Message-ID"); const subject = header(original, "Subject").replace(/^Re:\s*/i, "");
    await createDraft(`To: ${to}\r\nSubject: Re: ${subject}\r\nIn-Reply-To: ${messageId}\r\nReferences: ${messageId}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${flow.body}`, env, original.threadId);
  } else return { text: "⚠️ El borrador venció.", keyboard: await mainKeyboard(env) };
  await env.STORE.delete("flow");
  return { text: "💾 <b>Borrador guardado en Gmail</b>", keyboard: await mainKeyboard(env) };
}

async function listDrafts(env: Env): Promise<BotReply> {
  const list = await (await gmailFetch("drafts?maxResults=8", env)).json() as { drafts?: Array<{ id: string }> };
  if (!list.drafts?.length) return { text: "🗂️ No tienes borradores guardados.", keyboard: await mainKeyboard(env) };
  const drafts = await Promise.all(list.drafts.map(draft => gmailFetch(`drafts/${encodeURIComponent(draft.id)}?format=metadata`, env).then(r => r.json() as Promise<{ id: string; message: GmailMessage }>)));
  return { text: "🗂️ <b>Borradores guardados</b>", keyboard: { inline_keyboard: [...drafts.map((draft, index) => [{ text: `📝 ${index + 1}. ${(header(draft.message, "Subject") || "Sin asunto").slice(0, 35)}`, callback_data: `draft:open:${draft.id}` }]), [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
}

async function openDraft(id: string, env: Env): Promise<BotReply> {
  const draft = await (await gmailFetch(`drafts/${encodeURIComponent(id)}?format=full`, env)).json() as { id: string; message: GmailMessage };
  return { text: escapeHtml(`Para: ${header(draft.message, "To")}\nAsunto: ${header(draft.message, "Subject")}\n\n${decodeBody(draft.message)}`), keyboard: { inline_keyboard: [[{ text: "✅ Enviar borrador", callback_data: `draft:send:${id}` }, { text: "🗑️ Eliminar", callback_data: `draft:delete:${id}` }], [{ text: "🗂️ Volver", callback_data: "menu:drafts" }]] } };
}

async function sendDraft(id: string, env: Env): Promise<void> {
  await gmailFetch("drafts/send", env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id }) });
}

async function addVip(id: string, env: Env): Promise<BotReply> {
  const message = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=metadata&metadataHeaders=From`, env)).json() as GmailMessage;
  const from = header(message, "From"); const email = from.match(/<([^>]+)>/)?.[1] ?? from.trim();
  const vip = await env.STORE.get<string[]>("vip", "json") ?? [];
  if (email && !vip.includes(email.toLowerCase())) vip.push(email.toLowerCase());
  await env.STORE.put("vip", JSON.stringify(vip));
  return { text: `👑 <b>${escapeHtml(email)}</b> agregado a VIP. Sus correos activarán avisos inteligentes.`, keyboard: await readKeyboard(id, env) };
}

async function listVip(env: Env): Promise<BotReply> {
  const vip = await env.STORE.get<string[]>("vip", "json") ?? [];
  if (!vip.length) return { text: "👑 Aún no tienes contactos VIP. Abre un correo y usa <b>Marcar remitente VIP</b>.", keyboard: await mainKeyboard(env) };
  return { text: "👑 <b>Contactos VIP</b>", keyboard: { inline_keyboard: [...vip.map((email, index) => [{ text: `❌ ${email}`, callback_data: `vip:remove:${index}` }]), [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
}

async function removeVip(index: number, env: Env): Promise<BotReply> {
  const vip = await env.STORE.get<string[]>("vip", "json") ?? [];
  vip.splice(index, 1); await env.STORE.put("vip", JSON.stringify(vip));
  return listVip(env);
}

async function rememberContacts(value: string, env: Env): Promise<void> {
  const saved = await env.STORE.get<string[]>("contacts", "json") ?? [];
  const emails = value.split(/[,;]/).map(item => item.trim().match(/<?([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})>?/)?.[1]?.toLowerCase()).filter((item): item is string => Boolean(item));
  const contacts = [...emails, ...saved.filter(email => !emails.includes(email))].slice(0, 20);
  await env.STORE.put("contacts", JSON.stringify(contacts));
}

async function listContacts(env: Env): Promise<BotReply> {
  const contacts = await env.STORE.get<string[]>("contacts", "json") ?? [];
  if (!contacts.length) return { text: "👥 Aún no hay contactos frecuentes. Se guardan al enviar correos.", keyboard: await mainKeyboard(env) };
  return { text: "👥 <b>Contactos frecuentes</b>\nElige uno para redactar:", keyboard: { inline_keyboard: [...contacts.map((email, index) => [{ text: `✉️ ${email}`, callback_data: `contact:to:${index}` }]), [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
}

async function chooseContact(index: number, env: Env): Promise<BotReply> {
  const contacts = await env.STORE.get<string[]>("contacts", "json") ?? [];
  const to = contacts[index];
  if (!to) return { text: "⚠️ Contacto no encontrado.", keyboard: await mainKeyboard(env) };
  await env.STORE.put("flow", JSON.stringify({ type: "compose-subject", to } satisfies Flow), { expirationTtl: 600 });
  return { text: `✉️ <b>Nuevo correo para:</b> ${escapeHtml(to)}\nEscribe el asunto:`, keyboard: cancelKeyboard() };
}

type AuditEntry = { at: number; text: string };
async function audit(text: string, env: Env): Promise<void> {
  const entries = await env.STORE.get<AuditEntry[]>("history", "json") ?? [];
  entries.unshift({ at: Date.now(), text });
  await env.STORE.put("history", JSON.stringify(entries.slice(0, 40)));
}

async function listHistory(env: Env): Promise<BotReply> {
  const entries = await env.STORE.get<AuditEntry[]>("history", "json") ?? [];
  if (!entries.length) return { text: "📜 Aún no hay acciones registradas.", keyboard: await mainKeyboard(env) };
  return { text: `📜 <b>Actividad reciente</b>\n\n${entries.slice(0, 12).map(entry => `• ${new Date(entry.at).toLocaleString("es-PE", { timeZone: "America/Santiago" })} — ${escapeHtml(entry.text)}`).join("\n")}`, keyboard: await mainKeyboard(env) };
}

function ruleMenu(id: string): BotReply {
  return { text: "⚙️ <b>Regla automática para este remitente</b>", keyboard: { inline_keyboard: [[{ text: "📦 Archivar futuros correos", callback_data: `rule:archive:${id}` }], [{ text: "⭐ Destacar futuros correos", callback_data: `rule:star:${id}` }], [{ text: "↩️ Volver", callback_data: `mail:read:${id}` }]] } };
}

async function addRule(kind: keyof Rules, id: string, env: Env): Promise<BotReply> {
  const message = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=metadata&metadataHeaders=From`, env)).json() as GmailMessage;
  const source = (header(message, "From").match(/<([^>]+)>/)?.[1] ?? header(message, "From")).toLowerCase();
  const rules = await env.STORE.get<Rules>("rules", "json") ?? { archive: [], star: [] };
  if (!rules[kind].includes(source)) rules[kind].push(source);
  await env.STORE.put("rules", JSON.stringify(rules));
  await audit(`Regla creada: ${kind === "archive" ? "archivar" : "destacar"} correos de ${source}`, env);
  return { text: `⚙️ Regla activada para <b>${escapeHtml(source)}</b>.`, keyboard: await readKeyboard(id, env) };
}

async function messageCount(query: string, env: Env): Promise<number> {
  const result = await (await gmailFetch(`messages?maxResults=1&q=${encodeURIComponent(query)}`, env)).json() as { resultSizeEstimate?: number };
  return result.resultSizeEstimate ?? 0;
}

async function dashboard(env: Env): Promise<BotReply> {
  const [unread, important, scheduled, vip] = await Promise.all([
    messageCount("is:unread", env), messageCount("is:important", env), env.STORE.get<ScheduledMail[]>("scheduled-mail", "json"), env.STORE.get<string[]>("vip", "json")
  ]);
  return { text: `📊 <b>Panel de Gmail</b>\n\n🔴 No leídos: <b>${unread}</b>\n⭐ Importantes: <b>${important}</b>\n⏰ Programados: <b>${scheduled?.length ?? 0}</b>\n👑 Contactos VIP: <b>${vip?.length ?? 0}</b>`, keyboard: await mainKeyboard(env) };
}

async function alertPauseMenu(env: Env): Promise<BotReply> {
  const mutedUntil = Number(await env.STORE.get("alerts-muted-until") ?? 0);
  if (mutedUntil > Date.now()) return { text: `🔕 Alertas pausadas hasta ${new Date(mutedUntil).toLocaleString("es-PE", { timeZone: "America/Santiago" })}.`, keyboard: { inline_keyboard: [[{ text: "🔔 Reactivar ahora", callback_data: "alerts:unmute" }], [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
  return { text: "🔔 <b>Pausar alertas</b>", keyboard: { inline_keyboard: [[{ text: "🔕 1 hora", callback_data: "alerts:mute:1" }, { text: "🌙 8 horas", callback_data: "alerts:mute:8" }], [{ text: "🏠 Menú", callback_data: "menu:home" }]] } };
}

async function muteAlerts(hours: number, env: Env): Promise<BotReply> {
  const until = Date.now() + hours * 60 * 60 * 1000;
  await env.STORE.put("alerts-muted-until", String(until));
  return { text: `🔕 Alertas pausadas durante ${hours} hora${hours === 1 ? "" : "s"}.`, keyboard: await mainKeyboard(env) };
}

async function cleanupPromotions(env: Env): Promise<BotReply> {
  const list = await (await gmailFetch(`messages?maxResults=30&q=${encodeURIComponent("category:promotions in:inbox")}`, env)).json() as { messages?: Array<{ id: string }> };
  const messages = list.messages ?? [];
  await Promise.all(messages.map(message => messageAction("archive", message.id, env)));
  await audit(`Limpieza de promociones: ${messages.length} archivados`, env);
  return { text: `🧹 <b>Limpieza terminada</b>\n${messages.length} correos promocionales archivados.`, keyboard: await mainKeyboard(env) };
}

async function renewGmailWatch(env: Env): Promise<void> {
  if (!env.GMAIL_PUBSUB_TOPIC || !await activeAccount(env)) return;
  try {
    const response = await gmailFetch("watch", env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ topicName: env.GMAIL_PUBSUB_TOPIC, labelIds: ["INBOX"], labelFilterBehavior: "INCLUDE" }) });
    const watch = await response.json() as { expiration?: string; historyId?: string };
    await env.STORE.put("gmail-watch", JSON.stringify(watch));
    if (watch.historyId) await env.STORE.put("gmail-history", watch.historyId);
  } catch { /* The next daily schedule retries a transient Google failure. */ }
}

async function sendDailyDigestIfDue(env: Env): Promise<void> {
  if (!await activeAccount(env)) return;
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Santiago", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23" }).formatToParts(new Date());
  const value = (type: string) => parts.find(part => part.type === type)?.value ?? "";
  if (value("hour") !== "09") return;
  const dateKey = `${value("year")}-${value("month")}-${value("day")}`;
  if (await env.STORE.get("daily-digest-date") === dateKey) return;
  try {
    const [unread, starred] = await Promise.all([getMessageList("is:unread", 5, env), getMessageList("is:starred", 3, env)]);
    const lines = [
      "☀️ <b>Resumen diario de Gmail</b>",
      `🔴 No leídos: <b>${unread.length}${unread.length === 5 ? "+" : ""}</b>`,
      `⭐ Destacados: <b>${starred.length}${starred.length === 3 ? "+" : ""}</b>`
    ];
    if (unread.length) lines.push("", "<b>Por revisar:</b>", ...unread.slice(0, 3).map(mail => `• ${escapeHtml(header(mail, "Subject") || "Sin asunto")}`));
    await telegramSend(env, Number(env.TELEGRAM_OWNER_CHAT_ID), lines.join("\n"), { inline_keyboard: [[{ text: "📬 Abrir bandeja", callback_data: "menu:inbox" }]] });
    await env.STORE.put("daily-digest-date", dateKey);
  } catch { /* The next hourly run retries if Gmail is temporarily unavailable. */ }
}

async function sendWeeklyDigestIfDue(env: Env): Promise<void> {
  if (!await activeAccount(env)) return;
  const now = new Date();
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Santiago", weekday: "short", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23" }).formatToParts(now);
  const value = (type: string) => parts.find(part => part.type === type)?.value ?? "";
  if (value("weekday") !== "Mon" || value("hour") !== "09") return;
  const dateKey = `${value("year")}-${value("month")}-${value("day")}`;
  if (await env.STORE.get("weekly-digest-date") === dateKey) return;
  try {
    const [invoices, unread] = await Promise.all([getMessageList("newer_than:7d (factura OR invoice OR pago OR payment OR transferencia OR transfer)", 5, env), getMessageList("is:unread newer_than:7d", 5, env)]);
    const text = ["📊 <b>Resumen semanal</b>", `🧾 Facturas, pagos o transferencias: <b>${invoices.length}${invoices.length === 5 ? "+" : ""}</b>`, `🔴 No leídos de la semana: <b>${unread.length}${unread.length === 5 ? "+" : ""}</b>`].join("\n");
    await telegramSend(env, Number(env.TELEGRAM_OWNER_CHAT_ID), text, { inline_keyboard: [[{ text: "⚡ Ver facturas", callback_data: "filter:invoices" }, { text: "📬 Bandeja", callback_data: "menu:inbox" }]] });
    await env.STORE.put("weekly-digest-date", dateKey);
  } catch { /* retry on the next scheduled run */ }
}

async function processScheduledMail(env: Env): Promise<void> {
  const scheduled = await env.STORE.get<ScheduledMail[]>("scheduled-mail", "json") ?? [];
  if (!scheduled.length) return;
  const pending: ScheduledMail[] = [];
  for (const item of scheduled) {
    if (item.due > Date.now()) { pending.push(item); continue; }
    try {
      if (item.flow.type === "confirm-compose" && item.flow.to && item.flow.subject && item.flow.body) {
        await sendRaw(`To: ${item.flow.to}\r\nSubject: ${item.flow.subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${item.flow.body}`, env);
      } else if (item.flow.type === "confirm-reply" && item.flow.messageId && item.flow.body) {
        await reply(`${item.flow.messageId} | ${item.flow.body}`, env);
      } else continue;
      await telegramSend(env, Number(env.TELEGRAM_OWNER_CHAT_ID), "✅ <b>Correo programado enviado</b>");
    } catch { pending.push(item); }
  }
  await env.STORE.put("scheduled-mail", JSON.stringify(pending));
}

async function gmailPush(request: Request, url: URL, env: Env): Promise<Response> {
  if (!env.GMAIL_PUSH_KEY || url.searchParams.get("key") !== env.GMAIL_PUSH_KEY) return new Response("Unauthorized", { status: 401 });
  const payload = await request.json() as { message?: { data?: string } };
  if (!payload.message?.data) return new Response("Bad request", { status: 400 });
  try {
    const raw = payload.message.data.replace(/-/g, "+").replace(/_/g, "/");
    const notice = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(raw + "=".repeat((4 - raw.length % 4) % 4)), char => char.charCodeAt(0)))) as { historyId?: string };
    if (!notice.historyId || notice.historyId === await env.STORE.get("gmail-history")) return new Response("ok");
    await env.STORE.put("gmail-history", notice.historyId);
    if (Number(await env.STORE.get("alerts-muted-until") ?? 0) > Date.now()) return new Response("ok");
    const latest = await getMessageList("in:inbox newer_than:1d", 1, env);
    const mail = latest[0];
    if (mail) await applyRules(mail, env);
    const mode = await env.STORE.get("notification-mode") || "smart";
    if (mode === "smart" && mail && !await isSmartAlert(mail, env)) return new Response("ok");
    const subject = mail ? escapeHtml(header(mail, "Subject") || "Nuevo correo") : "Hay actividad nueva en Gmail";
    await telegramSend(env, Number(env.TELEGRAM_OWNER_CHAT_ID), `🔔 <b>${subject}</b>`, { inline_keyboard: [[{ text: "📬 Abrir bandeja", callback_data: "menu:inbox" }]] });
  } catch { return new Response("Bad request", { status: 400 }); }
  return new Response("ok");
}

async function isSmartAlert(mail: GmailMessage, env: Env): Promise<boolean> {
  if (mail.labelIds?.includes("IMPORTANT")) return true;
  const from = header(mail, "From").match(/<([^>]+)>/)?.[1]?.toLowerCase() ?? header(mail, "From").toLowerCase();
  if ((await env.STORE.get<string[]>("vip", "json") ?? []).includes(from)) return true;
  const text = `${header(mail, "Subject")} ${header(mail, "From")}`.toLowerCase();
  return /(urgente|urgent|seguridad|security|factura|invoice|pago|payment|transferencia|transfer|banco|bank|c[oó]digo|code|otp)/i.test(text);
}

async function applyRules(mail: GmailMessage, env: Env): Promise<void> {
  const rules = await env.STORE.get<Rules>("rules", "json") ?? { archive: [], star: [] };
  const sender = (header(mail, "From").match(/<([^>]+)>/)?.[1] ?? header(mail, "From")).toLowerCase();
  if (rules.archive.includes(sender)) await messageAction("archive", mail.id, env);
  if (rules.star.includes(sender)) await messageAction("star", mail.id, env);
}

async function messageAction(action: string, id: string, env: Env): Promise<void> {
  const safeId = encodeURIComponent(id);
  if (action === "trash") { await gmailFetch(`messages/${safeId}/trash`, env, { method: "POST" }); await audit("Correo enviado a la papelera", env); return; }
  if (action === "restore") { await gmailFetch(`messages/${safeId}/untrash`, env, { method: "POST" }); await audit("Correo recuperado de la papelera", env); return; }
  const changes: Record<string, { addLabelIds?: string[]; removeLabelIds?: string[] }> = {
    read: { removeLabelIds: ["UNREAD"] },
    unread: { addLabelIds: ["UNREAD"] },
    star: { addLabelIds: ["STARRED"] },
    archive: { removeLabelIds: ["INBOX"] },
    unspam: { removeLabelIds: ["SPAM"] }
  };
  const body = changes[action];
  if (!body) throw new Error("acción no válida");
  await gmailFetch(`messages/${safeId}/modify`, env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  await audit(`Correo: ${action}`, env);
}

async function messageActionWithLabel(id: string, labelId: string, env: Env): Promise<void> {
  await gmailFetch(`messages/${encodeURIComponent(id)}/modify`, env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ addLabelIds: [labelId] }) });
}

async function threadView(messageId: string, env: Env): Promise<BotReply> {
  const message = await (await gmailFetch(`messages/${encodeURIComponent(messageId)}?format=metadata`, env)).json() as GmailMessage;
  const thread = await (await gmailFetch(`threads/${encodeURIComponent(message.threadId)}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`, env)).json() as { messages?: GmailMessage[] };
  const messages = thread.messages ?? [];
  return { text: formatMessageList(messages, `🧵 Conversación (${messages.length} mensajes)`), keyboard: { inline_keyboard: [...messages.map((mail, index) => [{ text: `💬 ${index + 1}. ${(header(mail, "Subject") || "Sin asunto").slice(0, 35)}`, callback_data: `mail:read:${mail.id}` }]), [{ text: "↩️ Volver", callback_data: `mail:read:${messageId}` }]] } };
}

async function labelMenu(messageId: string, env: Env): Promise<BotReply> {
  const result = await (await gmailFetch("labels", env)).json() as { labels?: Array<{ id: string; name: string; type: string }> };
  const labels = (result.labels ?? []).filter(label => label.type === "user").slice(0, 12);
  return { text: "🏷️ <b>Aplicar etiqueta</b>", keyboard: { inline_keyboard: [
    ...labels.map(label => [{ text: `🏷️ ${label.name.slice(0, 38)}`, callback_data: `label:add:${messageId}:${label.id}` }]),
    [{ text: "➕ Crear etiqueta", callback_data: `label:create:${messageId}` }],
    [{ text: "↩️ Volver", callback_data: `mail:read:${messageId}` }]
  ] } };
}

async function addLabelToMessage(data: string, env: Env): Promise<BotReply> {
  const [, , messageId, labelId] = data.split(":");
  if (!messageId || !labelId) return { text: "⚠️ Etiqueta no válida.", keyboard: await mainKeyboard(env) };
  await messageActionWithLabel(messageId, labelId, env);
  return { text: "🏷️ Etiqueta aplicada al correo.", keyboard: await readKeyboard(messageId, env) };
}

function findAttachments(message: GmailMessage): Attachment[] {
  const attachments: Attachment[] = [];
  const collect = (part?: GmailMessage["payload"]): void => {
    if (!part) return;
    if (part.filename && part.body?.attachmentId) attachments.push({ messageId: message.id, attachmentId: part.body.attachmentId, filename: part.filename, mimeType: part.mimeType || "application/octet-stream", size: part.body.size });
    part.parts?.forEach(collect);
  };
  collect(message.payload);
  return attachments;
}

async function attachmentMenu(id: string, env: Env): Promise<BotReply> {
  const message = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=full`, env)).json() as GmailMessage;
  const attachments = findAttachments(message);
  if (!attachments.length) return { text: "📎 Este correo no tiene archivos adjuntos.", keyboard: await readKeyboard(id, env) };
  await env.STORE.put("attachments", JSON.stringify(attachments), { expirationTtl: 600 });
  return {
    text: `📎 <b>Adjuntos (${attachments.length})</b>\nElige un archivo para descargarlo en Telegram:`,
    keyboard: { inline_keyboard: [...attachments.map((file, index) => [{ text: `📄 ${file.filename.slice(0, 45)}`, callback_data: `mail:attachment:${index}` }]), [{ text: "↩️ Volver al correo", callback_data: `mail:read:${id}` }]] }
  };
}

async function sendAttachment(index: number, env: Env): Promise<void> {
  const attachments = await env.STORE.get<Attachment[]>("attachments", "json");
  const file = attachments?.[index];
  if (!file) throw new Error("el enlace del adjunto venció; vuelve a abrir el correo");
  if ((file.size ?? 0) > 20 * 1024 * 1024) throw new Error("el archivo supera el límite de 20 MB del bot");
  const result = await (await gmailFetch(`messages/${encodeURIComponent(file.messageId)}/attachments/${encodeURIComponent(file.attachmentId)}`, env)).json() as { data?: string };
  if (!result.data) throw new Error("Gmail no devolvió el archivo");
  const raw = result.data.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(raw + "=".repeat((4 - raw.length % 4) % 4)), c => c.charCodeAt(0));
  const form = new FormData();
  form.set("chat_id", env.TELEGRAM_OWNER_CHAT_ID);
  form.set("document", new Blob([bytes], { type: file.mimeType }), file.filename);
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendDocument`, { method: "POST", body: form });
  if (!response.ok) throw new Error("Telegram no pudo enviar el archivo");
}

async function getMessageList(query: string, count: number, env: Env): Promise<GmailMessage[]> {
  return (await getMessagePage(query, count, env)).messages;
}

async function getMessagePage(query: string, count: number, env: Env, pageToken?: string): Promise<{ messages: GmailMessage[]; nextPageToken?: string }> {
  const page = pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : "";
  const list = await (await gmailFetch(`messages?maxResults=${Math.min(Math.max(count, 1), 15)}&q=${encodeURIComponent(query)}${page}`, env)).json() as { messages?: Array<{ id: string }>; nextPageToken?: string };
  if (!list.messages?.length) return { messages: [] };
  const messages = await Promise.all(list.messages.map(m => gmailFetch(`messages/${m.id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`, env).then(r => r.json() as Promise<GmailMessage>)));
  return { messages, nextPageToken: list.nextPageToken };
}

async function renderPage(key: string, query: string, title: string, env: Env, direction?: string): Promise<BotReply> {
  let state: PageState;
  if (!direction) state = { query, title, tokens: [""], index: 0 };
  else {
    const saved = await env.STORE.get<PageState>(`page:${key}`, "json");
    if (!saved) return { text: "⚠️ Esta lista venció. Ábrela otra vez desde el menú.", keyboard: await mainKeyboard(env) };
    state = saved;
    if (direction === "next" && state.nextPageToken) { state.tokens = state.tokens.slice(0, state.index + 1); state.tokens.push(state.nextPageToken); state.index += 1; }
    if (direction === "prev" && state.index > 0) state.index -= 1;
  }
  const page = await getMessagePage(state.query, 8, env, state.tokens[state.index] || undefined);
  state.nextPageToken = page.nextPageToken;
  await env.STORE.put(`page:${key}`, JSON.stringify(state), { expirationTtl: 900 });
  return { text: formatMessageList(page.messages, state.title), keyboard: messageKeyboard(page.messages, { key, hasPrev: state.index > 0, hasNext: Boolean(page.nextPageToken) }) };
}

function formatMessageList(messages: GmailMessage[], title: string): string {
  if (!messages.length) return `${title}\n\nNo encontré correos.`;
  return `${title}\n\n${messages.map((m, index) => `<b>${index + 1}. ${escapeHtml(header(m, "Subject") || "Sin asunto")}</b>\n👤 ${escapeHtml(header(m, "From"))}`).join("\n\n")}`;
}

function decodeBody(message: GmailMessage): string {
  const allParts: NonNullable<GmailMessage["payload"]>[] = [];
  const collect = (part?: GmailMessage["payload"]): void => { if (!part) return; allParts.push(part); part.parts?.forEach(collect); };
  collect(message.payload);
  const part = allParts.find(p => p.mimeType === "text/plain" && p.body?.data) ?? allParts.find(p => p.mimeType === "text/html" && p.body?.data) ?? allParts.find(p => p.body?.data);
  if (!part?.body?.data) return message.snippet ?? "";
  try {
    const raw = part.body.data.replace(/-/g, "+").replace(/_/g, "/");
    const padded = raw + "=".repeat((4 - raw.length % 4) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
    let value = new TextDecoder("utf-8").decode(bytes);
    value = value.replace(/=\r?\n/g, "").replace(/=([A-F\d]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    if ((value.match(/%[A-F\d]{2}/gi)?.length ?? 0) > 4) { try { value = decodeURIComponent(value.replace(/\+/g, " ")); } catch { /* leave non-URL-encoded bodies alone */ } }
    if (part.mimeType === "text/html" || /<\/?[a-z][^>]*>/i.test(value)) value = htmlToText(value);
    return compactEmailText(value);
  } catch { return message.snippet ?? ""; }
}

function htmlToText(value: string): string {
  return value
    .replace(/<(br|hr)\s*\/?\s*>/gi, "\n")
    // Tables are common in bank and invoice emails.  Keep cell values together
    // so labels such as Monto and their value do not get glued together.
    .replace(/<\/(td|th)>/gi, " · ")
    .replace(/<\/(p|div|tr|li|h[1-6]|table|section)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;|&#160;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code)))
    .replace(/&#x([a-f\d]+);/gi, (_, code: string) => String.fromCodePoint(parseInt(code, 16)));
}

// Email HTML often uses invisible spacer rows. Telegram renders them as huge
// empty areas, so normalize every whitespace-only line and retain at most one
// blank line between actual paragraphs.
function compactEmailText(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .replace(/[\u00a0\u200b\ufeff]/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\s*·\s*\n/g, "\n")
    .replace(/\n{2,}/g, "\n\n")
    .trim();
}

function aiMenu(id: string): BotReply {
  return { text: "🤖 <b>Asistente de correo</b>", keyboard: { inline_keyboard: [[{ text: "📝 Resumir", callback_data: `ai:summary:${id}` }, { text: "🚨 Evaluar urgencia", callback_data: `ai:urgency:${id}` }], [{ text: "✍️ Sugerir respuesta", callback_data: `ai:reply:${id}` }], [{ text: "↩️ Volver", callback_data: `mail:read:${id}` }]] } };
}

async function openAiText(instructions: string, env: Env): Promise<string> {
  if (!env.OPENAI_API_KEY) throw new Error("la clave de IA no está configurada");
  const response = await fetch("https://api.openai.com/v1/responses", { method: "POST", headers: { "content-type": "application/json", Authorization: `Bearer ${env.OPENAI_API_KEY}` }, body: JSON.stringify({ model: "gpt-5-mini", input: instructions }) });
  if (!response.ok) throw new Error(`IA respondió ${response.status}`);
  const data = await response.json() as { output_text?: string };
  return data.output_text?.trim() || "No pude generar una respuesta.";
}

async function aiReadAction(action: "summary" | "urgency" | "reply", id: string, env: Env): Promise<BotReply> {
  const content = await readMessage(id, env);
  const prompts = {
    summary: "Resume este correo en español, en máximo 5 viñetas. No inventes información.",
    urgency: "Evalúa este correo en español. Indica nivel de urgencia (baja, media o alta), motivo y acción recomendada, de forma muy concisa.",
    reply: "Redacta una respuesta profesional breve en español para este correo. No inventes compromisos, fechas ni datos. Devuelve solo el texto de la respuesta."
  };
  const result = await openAiText(`${prompts[action]}\n\nCORREO:\n${content.slice(0, 12000)}`, env);
  if (action === "reply") { await env.STORE.put("flow", JSON.stringify({ type: "confirm-reply", messageId: id, body: result } satisfies Flow), { expirationTtl: 600 }); return { text: `✍️ <b>Respuesta sugerida</b>\n\n${escapeHtml(result)}`, keyboard: confirmKeyboard() }; }
  return { text: `${action === "summary" ? "📝 <b>Resumen</b>" : "🚨 <b>Urgencia</b>"}\n\n${escapeHtml(result)}`, keyboard: { inline_keyboard: [[{ text: "🤖 Más opciones", callback_data: `ai:menu:${id}` }], [{ text: "↩️ Correo", callback_data: `mail:read:${id}` }]] } };
}

async function handleVoice(fileId: string, env: Env): Promise<BotReply> {
  const flow = await env.STORE.get<Flow>("flow", "json");
  if (flow?.type !== "compose-body" && flow?.type !== "reply") return { text: "🎙️ Para dictar un correo, pulsa <b>Redactar</b> o <b>Responder</b> y, cuando pida el mensaje, envía una nota de voz.", keyboard: await mainKeyboard(env) };
  const fileInfo = await (await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`)).json() as { ok?: boolean; result?: { file_path?: string } };
  if (!fileInfo.ok || !fileInfo.result?.file_path) throw new Error("Telegram no pudo obtener el audio");
  const audio = await fetch(`https://api.telegram.org/file/bot${env.TELEGRAM_BOT_TOKEN}/${fileInfo.result.file_path}`);
  if (!audio.ok) throw new Error("no pude descargar la nota de voz");
  const form = new FormData(); form.set("model", "gpt-4o-mini-transcribe"); form.set("language", "es"); form.set("file", new Blob([await audio.arrayBuffer()], { type: "audio/ogg" }), "nota.ogg");
  const transcription = await fetch("https://api.openai.com/v1/audio/transcriptions", { method: "POST", headers: { Authorization: `Bearer ${env.OPENAI_API_KEY}` }, body: form });
  if (!transcription.ok) throw new Error(`IA respondió ${transcription.status}`);
  const data = await transcription.json() as { text?: string };
  if (!data.text) throw new Error("no entendí la nota de voz");
  return continueFlow(data.text, flow, env);
}

async function readMessage(id: string, env: Env): Promise<string> {
  const message = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=full`, env)).json() as GmailMessage;
  return text(`De: ${header(message, "From")}\nPara: ${header(message, "To")}\nAsunto: ${header(message, "Subject")}\nFecha: ${header(message, "Date")}\n\n${decodeBody(message)}`);
}

async function sendRaw(raw: string, env: Env, threadId?: string): Promise<void> {
  validateOutgoingRaw(raw);
  await gmailFetch("messages/send", env, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ raw: b64url(raw), ...(threadId ? { threadId } : {}) }) });
  await audit(threadId ? "Respuesta enviada" : "Correo enviado", env);
}

function validateOutgoingRaw(raw: string): void {
  const separator = raw.indexOf("\r\n\r\n");
  if (separator < 0) throw new Error("El formato del correo no es válido.");
  const allowed = new Set(["to", "subject", "mime-version", "content-type", "in-reply-to", "references"]);
  const seen = new Set<string>();
  for (const line of raw.slice(0, separator).split("\r\n")) {
    const colon = line.indexOf(":");
    if (colon < 1) throw new Error("El formato del correo no es válido.");
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1);
    if (!allowed.has(name) || seen.has(name) || /[\u0000-\u001f\u007f]/.test(value)) throw new Error("El correo contiene un encabezado no permitido.");
    seen.add(name);
  }
  if (!seen.has("to") || !seen.has("subject")) throw new Error("El correo necesita destinatario y asunto.");
}

async function reply(input: string, env: Env): Promise<string> {
  const [id, ...bodyParts] = input.split("|").map(s => s.trim()); const body = bodyParts.join("|");
  if (!id || !body) return "Uso: /reply ID | mensaje";
  const original = await (await gmailFetch(`messages/${encodeURIComponent(id)}?format=metadata&metadataHeaders=From&metadataHeaders=Reply-To&metadataHeaders=Subject&metadataHeaders=Message-ID`, env)).json() as GmailMessage;
  const to = header(original, "Reply-To") || header(original, "From"); const messageId = header(original, "Message-ID");
  const subject = header(original, "Subject").replace(/^Re:\s*/i, "");
  await sendRaw(`To: ${to}\r\nSubject: Re: ${subject}\r\nIn-Reply-To: ${messageId}\r\nReferences: ${messageId}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${body}`, env, original.threadId);
  return "Respuesta enviada.";
}

async function telegramRender(env: Env, chatId: number, reply: BotReply, messageId?: number): Promise<void> {
  const saved = messageId ? undefined : await env.STORE.get<UiState>("ui", "json");
  const targetId = messageId ?? saved?.messageId;
  if (targetId && await telegramEdit(env, chatId, targetId, reply.text, reply.keyboard)) {
    await env.STORE.put("ui", JSON.stringify({ messageId: targetId } satisfies UiState));
    return;
  }
  const createdId = await telegramSend(env, chatId, reply.text, reply.keyboard);
  if (createdId) await env.STORE.put("ui", JSON.stringify({ messageId: createdId } satisfies UiState));
}

async function telegramSend(env: Env, chatId: number, message: string, keyboard?: TelegramKeyboard): Promise<number | undefined> {
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: chatId, text: text(message), parse_mode: "HTML", ...(keyboard ? { reply_markup: keyboard } : {}) }) });
  const data = await response.json().catch(() => undefined) as { ok?: boolean; result?: { message_id?: number } } | undefined;
  return data?.ok ? data.result?.message_id : undefined;
}

async function telegramEdit(env: Env, chatId: number, messageId: number, message: string, keyboard?: TelegramKeyboard): Promise<boolean> {
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/editMessageText`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: chatId, message_id: messageId, text: text(message), parse_mode: "HTML", ...(keyboard ? { reply_markup: keyboard } : {}) }) });
  if (response.ok) return true;
  const data = await response.json().catch(() => undefined) as { description?: string } | undefined;
  return data?.description?.includes("message is not modified") ?? false;
}

async function telegramAnswerCallback(env: Env, callbackId: string): Promise<void> {
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ callback_query_id: callbackId }) });
}

async function telegramDelete(env: Env, chatId: number, messageId: number): Promise<void> {
  // PIN messages are removed immediately after reaching the bot, whether the
  // PIN is correct or not, so the numeric value does not remain in the chat.
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/deleteMessage`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: chatId, message_id: messageId }) });
  } catch { /* Do not block PIN validation if Telegram cannot delete it. */ }
}
