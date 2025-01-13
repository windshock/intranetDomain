
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// 로그 유틸리티
function logDebug(message, data = null) {
    const timestamp = new Date().toISOString();
    console.log(`[DEBUG] [${timestamp}] ${message}`);
    if (data) {
        console.log(`[DATA]`, data);
    }
}

// 공개 키 제공 엔드포인트
app.get("/public-key", (req, res) => {
    logDebug("Request received at /public-key");
    const publicKeyPath = path.join(__dirname, "public.pem");
    if (!fs.existsSync(publicKeyPath)) {
        logDebug("Public key not found");
        return res.status(404).send("Public key not found");
    }
    const publicKey = fs.readFileSync(publicKeyPath, "utf8");
    logDebug("Public key sent successfully");
    res.setHeader("Content-Type", "text/plain");
    res.send(publicKey);
});

// IV 요청 엔드포인트
app.get("/request-iv", (req, res) => {
    logDebug("Request received at /request-iv");
    const iv = crypto.randomBytes(16).toString("base64");
    const timestamp = Date.now();
    logDebug("Generated IV", { iv, timestamp });
    res.json({ iv });
});

// 검증 엔드포인트
app.post("/validate", (req, res) => {
    logDebug("Request received at /validate", req.body);
    const { encryptedData, encryptedKey, iv } = req.body;

    try {
        if (!encryptedData || !encryptedKey || !iv) {
            logDebug("Validation failed: Missing fields", req.body);
            return res.status(400).json({ success: false, message: "Invalid data structure" });
        }

        logDebug("Validation passed", { encryptedDataLength: encryptedData.length });
        res.json({ success: true, message: "Validation successful", downloadUrl: "/download/file.zip" });
    } catch (error) {
        logDebug("Error during validation", error.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// 파일 다운로드 엔드포인트
app.get("/download/:file", (req, res) => {
    const file = req.params.file;
    logDebug(`Download request received for file: ${file}`);
    const filePath = path.join(__dirname, "files", file);

    if (!fs.existsSync(filePath)) {
        logDebug("File not found", { file });
        return res.status(404).send("File not found");
    }

    res.download(filePath, (err) => {
        if (err) {
            logDebug("Error during file download", err.message);
            res.status(500).send("Error during file download");
        } else {
            logDebug("File downloaded successfully", { file });
        }
    });
});

const HTTP_PORT = 80;

// HTTP 서버 실행
app.listen(HTTP_PORT, () => {
    logDebug(`HTTP server running on port ${HTTP_PORT}`);
});
