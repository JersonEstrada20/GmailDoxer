# Bot de Telegram para Gmail en Cloudflare

Bot personal para consultar, buscar, leer, enviar y responder correos de una sola cuenta Gmail desde Telegram. Se ejecuta en Cloudflare Workers, por lo que no depende de un servidor encendido continuamente.

## 1. Crea el bot de Telegram

1. Abre **@BotFather** en Telegram, ejecuta `/newbot` y guarda el token.
2. Abre una conversación con tu bot y envía `/start`.
3. Obtén tu `chat_id`: abre `https://api.telegram.org/bot<TU_TOKEN>/getUpdates` en el navegador y copia `message.chat.id`.

## 2. Prepara Google

1. En [Google Cloud Console](https://console.cloud.google.com/), crea un proyecto y habilita **Gmail API**.
2. Configura la pantalla de consentimiento OAuth. Si queda en modo prueba, añádete como usuario de prueba.
3. Crea credenciales **OAuth client ID > Web application**. La URL de retorno se añade después del primer despliegue: `https://TU-WORKER.TU-SUBDOMINIO.workers.dev/auth/callback`.

## 3. Instala y despliega

```powershell
npm install
npx wrangler login
npx wrangler deploy
```

Cloudflare imprimirá la URL pública del Worker. Colócala como URL de retorno en Google, y guarda esa misma URL como secreto `APP_URL`.

```powershell
npx wrangler secret put APP_URL
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET
npx wrangler secret put TELEGRAM_OWNER_CHAT_ID
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put AUTH_START_KEY
npx wrangler deploy
```

Usa claves largas y aleatorias para `TELEGRAM_WEBHOOK_SECRET` y `AUTH_START_KEY`. No las compartas.

## 4. Activa el webhook

Sustituye los valores y ejecuta una vez:

```powershell
$token = "TOKEN_DE_BOTFATHER"
$url = "https://TU-WORKER.TU-SUBDOMINIO.workers.dev/telegram"
$secret = "EL_MISMO_TELEGRAM_WEBHOOK_SECRET"
Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$token/setWebhook" -Body @{ url = $url; secret_token = $secret }
```

En Telegram usa `/connect`, abre el enlace privado y autoriza Gmail.

## Comandos

```text
/inbox 8
/search from:cliente@example.com newer_than:7d
/read ID_DEL_CORREO
/send destinatario@ejemplo.com | Asunto | Mensaje
/reply ID_DEL_CORREO | Mensaje
/disconnect
```

El bot solo atiende el `TELEGRAM_OWNER_CHAT_ID` configurado y valida el secreto del webhook. Los tokens de Gmail se guardan en Cloudflare KV y nunca se incluyen en el repositorio. Consulta la [política de privacidad](https://telegram-gmail-bot.jersonestrada50.workers.dev/privacy) para conocer el tratamiento de datos.
