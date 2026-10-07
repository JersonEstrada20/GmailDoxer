# Asistente de correo en Telegram

Bot personal para consultar, buscar, leer, enviar y responder correos de Gmail desde Telegram. Se ejecuta en Cloudflare Workers y no depende de un servidor encendido continuamente.

## Requisitos

- Node.js y pnpm.
- Una cuenta de Cloudflare con Workers y KV.
- Un bot creado con [@BotFather](https://t.me/BotFather).
- Un proyecto de Google Cloud con Gmail API habilitada y un cliente OAuth de tipo **Web application**.

## Desarrollo local

```powershell
pnpm install
Copy-Item .dev.vars.example .dev.vars
pnpm dev
```

Completa `.dev.vars` con tus valores locales. No lo subas a Git: está incluido en `.gitignore`.

Genera valores aleatorios para `TELEGRAM_WEBHOOK_SECRET`, `AUTH_START_KEY` y `TOKEN_ENCRYPTION_KEY` con PowerShell:

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
-join ($bytes | ForEach-Object { $_.ToString('x2') })
```

Ejecuta el comando por separado para cada clave. `TOKEN_ENCRYPTION_KEY` debe tener 64 caracteres hexadecimales. Guarda una copia segura: si se pierde o cambia, los tokens cifrados de Gmail ya no podrán descifrarse y habrá que conectar Gmail nuevamente.

## Publicar en Cloudflare

1. Inicia sesión y publica el Worker:

   ```powershell
   pnpm exec wrangler login
   pnpm deploy
   ```

2. Copia la URL que muestra Wrangler y úsala en `APP_URL` y como URI de redirección autorizada del cliente OAuth, con esta ruta:

   ```text
   https://TU-WORKER.TU-SUBDOMINIO.workers.dev/auth/callback
   ```

3. Carga cada valor de producción como secreto de Wrangler. Ejecuta cada comando y pega el valor cuando Wrangler lo solicite:

   ```powershell
   pnpm exec wrangler secret put APP_URL
   pnpm exec wrangler secret put TELEGRAM_BOT_TOKEN
   pnpm exec wrangler secret put TELEGRAM_WEBHOOK_SECRET
   pnpm exec wrangler secret put TELEGRAM_OWNER_CHAT_ID
   pnpm exec wrangler secret put GOOGLE_CLIENT_ID
   pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET
   pnpm exec wrangler secret put AUTH_START_KEY
   pnpm exec wrangler secret put TOKEN_ENCRYPTION_KEY
   ```

   `OPENAI_API_KEY` es opcional y habilita las funciones de IA y transcripción de voz. No cargues el `.dev.vars` local completo a producción: usa los secretos de Wrangler.

4. Vuelve a publicar después de modificar código o configuración:

   ```powershell
   pnpm deploy
   ```

El Worker requiere un namespace KV enlazado como `STORE`; el ID de este proyecto está en `wrangler.jsonc`. También ejecuta una tarea programada cada hora para procesar correos programados y resúmenes.

## Activar Telegram y Gmail

Configura el webhook una vez. Sustituye los valores localmente y no compartas el token:

```powershell
$token = "TOKEN_DE_BOTFATHER"
$url = "https://TU-WORKER.TU-SUBDOMINIO.workers.dev/telegram"
$secret = "EL_MISMO_TELEGRAM_WEBHOOK_SECRET"
Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$token/setWebhook" -Body @{ url = $url; secret_token = $secret }
```

En Telegram, envía `/start` y luego `/connect` para autorizar la cuenta de Gmail. La cuenta de Google debe estar como usuario de prueba si el consentimiento OAuth está en modo de prueba. En ese modo, Google caduca los permisos después de siete días; al pasar la app a producción, el token nuevo deja de tener ese límite específico, aunque Google puede solicitar verificaciones adicionales.

## Comandos

```text
/inbox 8
/search from:cliente@example.com newer_than:7d
/read ID_DEL_CORREO
/send destinatario@ejemplo.com | Asunto | Mensaje
/reply ID_DEL_CORREO | Mensaje
/disconnect
```

El bot solo atiende al `TELEGRAM_OWNER_CHAT_ID` configurado y valida el secreto del webhook. Los tokens OAuth de Gmail se cifran con AES-GCM antes de guardarse en Cloudflare KV; los secretos y claves no se incluyen en el repositorio. La página de la aplicación y la [política de privacidad](https://telegram-gmail-bot.jersonestrada50.workers.dev/privacy) están publicadas en el Worker.
