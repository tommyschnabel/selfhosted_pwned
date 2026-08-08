/**
 * @jest-environment jsdom
 */

const CryptoJS = require('crypto-js');

const { toSha1Hash, resultFor, wireUp } = require('./index');

// sha1 of "password", lowercase.
const PASSWORD_HASH = '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8';

describe('toSha1Hash', () => {
    test('hashes a plain password', () => {
        expect(toSha1Hash('password')).toBe(PASSWORD_HASH);
    });

    test('passes an existing lowercase hash through untouched', () => {
        expect(toSha1Hash(PASSWORD_HASH)).toBe(PASSWORD_HASH);
    });

    test('passes an existing uppercase hash through untouched', () => {
        const upper = PASSWORD_HASH.toUpperCase();
        expect(toSha1Hash(upper)).toBe(upper);
    });

    test('a 39-character hex string is treated as a password, not a hash', () => {
        const almost = PASSWORD_HASH.slice(0, 39);
        expect(toSha1Hash(almost)).toBe(CryptoJS.SHA1(almost).toString());
    });

    test('a 40-character non-hex string is treated as a password', () => {
        const notHex = 'z'.repeat(40);
        expect(toSha1Hash(notHex)).toBe(CryptoJS.SHA1(notHex).toString());
    });
});

describe('resultFor', () => {
    test('an error payload wins over everything else', () => {
        expect(resultFor({ error: 'upstream down', found: true, count: 5 })).toEqual({
            message: 'Error: upstream down',
            type: 'error',
        });
    });

    test('a breached password reports the count', () => {
        const { message, type } = resultFor({ found: true, count: 9659365 });
        expect(type).toBe('warning');
        expect(message).toContain('9659365');
    });

    test('a clean password is reported as success', () => {
        expect(resultFor({ found: false }).type).toBe('success');
    });
});

describe('form wiring', () => {
    let handles;

    beforeEach(() => {
        document.body.innerHTML = `
            <form id="checkerForm">
                <input id="password" type="password" />
                <button id="togglePassword"></button>
            </form>
            <div id="result"></div>
            <div id="loading"></div>
        `;
        handles = wireUp();
    });

    afterEach(() => {
        delete global.fetch;
    });

    test('an empty input is rejected without calling the API', async () => {
        global.fetch = jest.fn();
        document.getElementById('password').value = '   ';

        await handles.checkPassword();

        expect(global.fetch).not.toHaveBeenCalled();
        expect(document.getElementById('result').textContent).toMatch(/Please enter/);
    });

    test('only the hash is sent to the server, never the password', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ found: false }),
        });
        document.getElementById('password').value = 'password';

        await handles.checkPassword();

        const [url, options] = global.fetch.mock.calls[0];
        expect(url).toBe('/api/check/hash');
        expect(JSON.parse(options.body)).toEqual({ hash: PASSWORD_HASH });
        expect(options.body).not.toContain('password"');
    });

    test('a breach is rendered as a warning', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ found: true, count: 42 }),
        });
        document.getElementById('password').value = 'password';

        await handles.checkPassword();

        const result = document.getElementById('result');
        expect(result.className).toContain('warning');
        expect(result.textContent).toContain('42');
    });

    test('a non-ok response shows the server text', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            text: async () => 'Invalid SHA1 hash',
        });
        document.getElementById('password').value = 'password';

        await handles.checkPassword();

        expect(document.getElementById('result').textContent).toBe('Error: Invalid SHA1 hash');
    });

    test('a network failure is shown rather than thrown', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('offline'));
        document.getElementById('password').value = 'password';

        await handles.checkPassword();

        expect(document.getElementById('result').textContent).toBe('Error: offline');
        expect(document.getElementById('loading').classList.contains('show')).toBe(false);
    });

    test('the loading indicator is cleared after a successful check', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ found: false }),
        });
        document.getElementById('password').value = 'password';

        await handles.checkPassword();

        expect(document.getElementById('loading').classList.contains('show')).toBe(false);
    });

    test('the toggle button flips the input between password and text', () => {
        const input = document.getElementById('password');
        const toggle = document.getElementById('togglePassword');

        toggle.click();
        expect(input.getAttribute('type')).toBe('text');
        expect(toggle.classList.contains('showing')).toBe(true);

        toggle.click();
        expect(input.getAttribute('type')).toBe('password');
        expect(toggle.classList.contains('showing')).toBe(false);
    });

    test('submitting the form checks the password and suppresses navigation', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ found: false }),
        });
        document.getElementById('password').value = 'password';

        const event = new Event('submit', { cancelable: true });
        document.getElementById('checkerForm').dispatchEvent(event);
        await Promise.resolve();
        await Promise.resolve();

        expect(event.defaultPrevented).toBe(true);
        expect(global.fetch).toHaveBeenCalled();
    });
});
