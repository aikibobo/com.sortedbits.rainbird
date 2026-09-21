// Check an LNK device password against the controller, in one request.
//
// Deliberately does NOT use RainBirdService.init(): the library retries a failed
// request forever (sendRequest loops on `retry: true`), so a wrong password hangs
// instead of failing. One raw request gives a verdict in well under a second:
// HTTP 403 "Invalid Password" = wrong, HTTP 200 = right.
//
// Usage: RB_PASSWORD=... [RB_HOST=192.168.1.87] node tools/test-lnk.mjs
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import aesjs from 'aes-js';
import { request, Agent } from 'undici';

const host = process.env.RB_HOST || '192.168.1.87';
const password = process.env.RB_PASSWORD ?? '';

if (!password) {
    console.error('Geen wachtwoord. Zet RB_PASSWORD.');
    process.exit(2);
}

const pad = (s) => s + '\x00'.repeat((16 - (s.length % 16)) % 16);
const bytes = (s) => new TextEncoder().encode(s);

function encrypt(sipCommand) {
    const body = JSON.stringify({
        id: 9,
        jsonrpc: '2.0',
        method: 'tunnelSip',
        params: { data: sipCommand.toString('hex'), length: sipCommand.length },
    });
    const key = crypto.createHash('sha256').update(bytes(password)).digest();
    const iv = crypto.randomBytes(16);
    const bodyHash = crypto.createHash('sha256').update(bytes(body)).digest();
    const cipher = new aesjs.ModeOfOperation.cbc(key, iv);
    return Buffer.concat([bodyHash, iv, Buffer.from(cipher.encrypt(bytes(pad(body))))]);
}

function decrypt(buf) {
    const key = crypto.createHash('sha256').update(bytes(password)).digest().subarray(0, 32);
    const decipher = new aesjs.ModeOfOperation.cbc(key, buf.subarray(32, 48));
    return new TextDecoder().decode(decipher.decrypt(buf.subarray(48))).replace(/[\x10\n\0]/g, '');
}

const agent = new Agent({ connect: { rejectUnauthorized: false } });

let res;
try {
    res = await request(`https://${host}/stick`, {
        method: 'POST',
        body: encrypt(Buffer.from([0x02])), // ModelAndVersion
        dispatcher: agent,
        headers: {
            'Accept-Language': 'en',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'RainBird/2.0 CFNetwork/811.5.4 Darwin/16.7.0',
            Accept: '*/*',
            Connection: 'keep-alive',
            'Content-Type': 'application/octet-stream',
        },
        headersTimeout: 10000,
        bodyTimeout: 10000,
    });
} catch (e) {
    console.error(`FOUT: ${host} niet bereikbaar (${e.code || e.message}).`);
    process.exit(1);
}

const raw = Buffer.from(await res.body.arrayBuffer());

if (res.statusCode === 403) {
    console.error('FOUT: wachtwoord afgewezen door de module (HTTP 403 "Invalid Password").');
    process.exit(1);
}
if (res.statusCode !== 200) {
    console.error(`FOUT: onverwachte HTTP ${res.statusCode}: ${raw.toString('utf8').slice(0, 120)}`);
    process.exit(1);
}

let payload;
try {
    payload = JSON.parse(decrypt(raw));
} catch {
    console.error('FOUT: antwoord niet te ontsleutelen. Wachtwoord klopt niet.');
    process.exit(1);
}

if (payload.error) {
    console.error(`FOUT: controller gaf ${payload.error.code}: ${payload.error.message}`);
    process.exit(1);
}

// tunnelSip result: 82 <model:2 bytes> <major> <minor>
const data = Buffer.from(payload.result.data, 'hex');
console.log('GOED. Wachtwoord klopt.');
console.log('  model     0x' + data.subarray(1, 3).toString('hex'));
console.log('  firmware  ' + data[3] + '.' + data[4]);
console.log('  gebruik dit wachtwoord in de Homey-pairing, host ' + host);
process.exit(0);
