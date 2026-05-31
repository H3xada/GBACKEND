import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';
  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

// @note helper to extract client data from any format iOS/Android/Windows sends
function extractClientData(req: Request): string {
  const body = req.body;

  // Standard — body is object with client data as first key
  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    const firstKey = Object.keys(body)[0];
    // Make sure it looks like actual client data (contains | separators)
    if (firstKey && firstKey.includes('|')) return firstKey;
    // Or if the value contains client data
    const firstVal = body[firstKey];
    if (firstVal && typeof firstVal === 'string' && firstVal.includes('|')) return firstVal;
    // Return first key anyway as fallback
    if (firstKey && firstKey.length > 0) return firstKey;
  }

  // iOS may send as raw string body
  if (typeof body === 'string' && body.length > 0) return body;

  // iOS may send clientData as a named field
  if (body?.clientData && typeof body.clientData === 'string') return body.clientData;

  // iOS may send as query parameter
  if (req.query) {
    const queryKeys = Object.keys(req.query);
    for (const key of queryKeys) {
      const val = req.query[key] as string;
      if (val && val.includes('|')) return val;
      if (key && key.includes('|')) return key;
    }
  }

  return '';
}

// @note serve dashboard template
function serveDashboard(req: Request, res: Response) {
  const clientData = extractClientData(req);
  console.log(`[DASHBOARD] clientData length: ${clientData.length} | empty: ${clientData.length === 0}`);

  const encodedClientData = Buffer.from(clientData).toString('base64');
  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
}

app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

// @note dashboard — login page
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  serveDashboard(req, res);
});

// @note validate login — packages credentials into base64 token for C++ server
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const _token   = formData._token   || '';
    const growId   = formData.growId   || '';
    const password = formData.password || '';
    const email    = formData.email;

    let token = '';
    if (email) {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&email=${email}&reg=1`,
      ).toString('base64');
    } else {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&reg=0`,
      ).toString('base64');
    }

    console.log(`[VALIDATE] growId: ${growId} | hasToken: ${_token.length > 0}`);

    res.send(JSON.stringify({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
    }));
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({ status: 'error', message: 'Internal Server Error' });
  }
});

// @note checktoken redirect
app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

// @note checktoken — handles session resume (iOS background, reconnect)
app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;
    let clientData:   string | undefined;
    let source = 'empty';
    const contentType = req.headers['content-type'] || '';

    if (typeof req.body === 'object' && req.body !== null) {
      const formData = req.body as Record<string, string>;

      if ('refreshToken' in formData || 'clientData' in formData) {
        refreshToken = formData.refreshToken;
        clientData   = formData.clientData;
        source = contentType.includes('application/json') ? 'json/object' : 'form-urlencoded';
      } else if (Object.keys(formData).length === 1) {
        const rawPayload = Object.keys(formData)[0];
        const params = new URLSearchParams(rawPayload);
        refreshToken = params.get('refreshToken') || undefined;
        clientData   = params.get('clientData')   || undefined;
        if (refreshToken || clientData) source = 'single-key-form-payload';
      }
    } else if (typeof req.body === 'string' && req.body.length > 0) {
      const params = new URLSearchParams(req.body);
      refreshToken = params.get('refreshToken') || undefined;
      clientData   = params.get('clientData')   || undefined;
      source = 'string/body-parser';
    }

    // Fallback raw stream
    if ((!refreshToken || !clientData) && req.readable && !req.readableEnded) {
      const rawBody = await new Promise<string>((resolve, reject) => {
        let rawPayload = '';
        req.on('data', (chunk: Buffer | string) => { rawPayload += chunk.toString(); });
        req.on('end',  () => resolve(rawPayload));
        req.on('error', reject);
      });
      if (rawBody) {
        const params = new URLSearchParams(rawBody);
        refreshToken = params.get('refreshToken') || refreshToken;
        clientData   = params.get('clientData')   || clientData;
        if (refreshToken || clientData) source = 'raw-stream';
      }
    }

    console.log(`[CHECKTOKEN] source: ${source} | hasToken: ${!!refreshToken} | hasData: ${!!clientData}`);

    if (!refreshToken || !clientData) {
      console.log(`[CHECKTOKEN ERROR]: Missing refreshToken or clientData`);
      res.status(200).json({ status: 'error', message: 'Missing refreshToken or clientData' });
      return;
    }

    // Decode refresh token
    let decodedToken: string;
    try {
      decodedToken = Buffer.from(refreshToken, 'base64').toString('utf-8');
    } catch {
      console.log(`[CHECKTOKEN ERROR]: Failed to decode refreshToken`);
      res.status(200).json({ status: 'error', message: 'Invalid token encoding' });
      return;
    }

    // Strip all reg= variants — iOS may send different formats
    decodedToken = decodedToken
      .replace(/&reg=\d+/g, '')
      .replace(/\?reg=\d+/g, '')
      .replace(/^reg=\d+&/g, '');

    // Encode new clientData
    const encodedClientData = Buffer.from(clientData).toString('base64');

    // Replace _token value with fresh clientData
    let newToken: string;
    if (decodedToken.includes('_token=')) {
      newToken = Buffer.from(
        decodedToken.replace(/(_token=)[^&]*/, `$1${encodedClientData}`)
      ).toString('base64');
    } else {
      // _token missing — reconstruct full token
      // This handles iOS edge case where token arrives without _token field
      newToken = Buffer.from(
        `_token=${encodedClientData}&${decodedToken}`
      ).toString('base64');
    }

    res.send(JSON.stringify({
      status:      'success',
      message:     'Account Validated.',
      token:       newToken,
      url:         '',
      accountType: 'growtopia',
      accountAge:  365,
    }));

  } catch (error) {
    console.log(`[CHECKTOKEN ERROR]: ${error}`);
    res.status(200).json({ status: 'error', message: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
