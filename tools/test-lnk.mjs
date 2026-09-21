// Probe a Rain Bird LNK module with a candidate password, without touching the app.
// Usage: RB_HOST=192.168.1.87 RB_PASSWORD=... node tools/test-lnk.mjs
import { RainBirdService } from 'rainbird/dist/RainBird/RainBirdService.js';

const address = process.env.RB_HOST || '192.168.1.87';
const password = process.env.RB_PASSWORD || '';

if (!password) {
    console.error('Geen wachtwoord. Zet RB_PASSWORD.');
    process.exit(2);
}

const service = new RainBirdService({ address, password, syncTime: false, showRequestResponse: false, refreshRate: 0 });

const timer = setTimeout(() => {
    console.error(`FOUT: geen bruikbaar antwoord van ${address} binnen 25s (verkeerd wachtwoord of module reageert niet).`);
    process.exit(1);
}, 25000);

try {
    const meta = await service.init();
    clearTimeout(timer);
    if (!meta?.model) {
        console.error('FOUT: verbonden maar geen model terug. Wachtwoord vrijwel zeker fout.');
        process.exit(1);
    }
    console.log('GOED. Wachtwoord klopt.');
    console.log('  model       ', meta.model, `(${meta.modelNumber})`);
    console.log('  firmware    ', meta.version);
    console.log('  serienummer ', meta.serialNumber);
    console.log('  zones       ', JSON.stringify(meta.zones));
    process.exit(0);
} catch (e) {
    clearTimeout(timer);
    console.error('FOUT:', e?.message || e);
    process.exit(1);
}
