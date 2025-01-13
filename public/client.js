// 스크립트 태그로 JSEncrypt 라이브러리를 로드
    console.log("JSEncrypt library loaded!");

    const serverUrl = `https://${window.location.hostname}`; // "https://disabled-begins-extra-turner.trycloudflare.com"; // 서버 URL 설정
    const publicKeyUrl = `${serverUrl}/public-key`;
    const ivUrl = `${serverUrl}/request-iv`;
    const domainsUrl = `${serverUrl}/domains`;

    // 공개 키 가져오기
    async function fetchPublicKey() {
        const response = await fetch(publicKeyUrl);
        if (!response.ok) {
            throw new Error("Failed to fetch public key");
        }
        return response.text();
    }

    // IV 값 가져오기
    async function fetchIV() {
        const response = await fetch(ivUrl);
        if (!response.ok) {
            throw new Error("Failed to fetch IV");
        }
        const { iv } = await response.json();
        console.log("[DEBUG] IV fetched:", iv);
        return iv;
    }

    // 도메인 목록 가져오기
    async function fetchDomains() {
        const response = await fetch(domainsUrl);
        if (!response.ok) {
            throw new Error("Failed to fetch domains");
        }
    
        const text = await response.text(); // 텍스트 데이터 가져오기
    
        try {
            // 공백과 줄바꿈 제거 후 JSON 파싱
            const trimmedText = text.trim(); // 공백과 줄바꿈 제거
            const domains = JSON.parse(trimmedText); // JSON 배열로 파싱
    
            if (!Array.isArray(domains)) {
                throw new Error("Domains data is not a valid array");
            }
    
            return domains.filter(domain => domain.trim() !== ""); // 빈 도메인 제거
        } catch (error) {
            console.error("[ERROR] Failed to parse domains:", error.message);
            throw error;
        }
    }

    // fetch 요청에 3초 제한 추가
    async function fetchWithTimeout(url, options = {}, timeout = 3000) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, { ...options, signal: controller.signal });
            clearTimeout(timeoutId); // 성공 시 타임아웃 해제
            return response; // 성공적인 응답 반환
        } catch (error) {
            if (error.name === "AbortError") {
                console.error(`[ERROR] Request to ${url} timed out after ${timeout}ms`);
            } else {
                console.error(`[ERROR] Request to ${url} failed:`, error);
            }
            throw error; // 에러 다시 던지기
        }
    }

    // 도메인 실행 시간 측정
    async function checkDomainWithTimeout(domain) {
        const protocols = ["http://", "https://"];
        let data = {
            domain,
            url: null,
            responseType: null,
            elapsedTime: null,
            error: null,
        };

        for (const protocol of protocols) {
            const url = `${protocol}${domain}`;
            const startTime = performance.now();
            try {
                await fetchWithTimeout(url, { method: "HEAD", mode: "no-cors" }, 3000); // 3초 제한
                const endTime = performance.now();
                data = {
                    domain,
                    url,
                    responseType: "opaque",
                    elapsedTime: (endTime - startTime).toFixed(2),
                    error: null,
                };
                console.log(`[DEBUG] ${url} responded in ${data.elapsedTime} ms`);
                return data; // 성공하면 결과 반환
            } catch (error) {
                const endTime = performance.now();
                data.elapsedTime = (endTime - startTime).toFixed(2);
                data.error = error.name === "AbortError" ? "Timeout" : error.message;
                console.warn(`[WARN] ${url} failed: ${data.error}`);
            }
        }
        return data; // 모든 프로토콜 실패 시 데이터 반환
    }

    // AES 암호화
    async function aesEncrypt(data, aesKey, iv) {
        console.log("[DEBUG] AES encryption started...");
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(JSON.stringify(data));
        console.log("aesKey : ",aesKey)
        const key = await crypto.subtle.importKey(
            "raw", // 키 형식
            aesKey, // AES 키
            { name: "AES-CBC" }, // 암호화 방식
            false, // 키 내보내기 비허용
            ["encrypt"]
        );

        const ivArray = new Uint8Array(atob(iv).split("").map(char => char.charCodeAt(0))); // IV 디코딩
        if (ivArray.length !== 16) {
            throw new Error("[ERROR] IV must be 16 bytes long.");
        }

        const encryptedData = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv: ivArray },
            key,
            encodedData
        );

        console.log("[DEBUG] AES encryption completed.");
        return new Uint8Array(encryptedData); // 암호화된 데이터 반환
    }

    // RSA로 AES 키 암호화
    function rsaEncryptAesKey(aesKey, publicKey) {
        const encryptor = new JSEncrypt();
        encryptor.setPublicKey(publicKey);
        const encryptedKey = encryptor.encrypt(String.fromCharCode(...aesKey));
        if (!encryptedKey) {
            throw new Error("[ERROR] RSA encryption failed for AES key.");
        }
        return encryptedKey;
    }

    // 하이브리드 암호화 (AES + RSA)
    async function hybridEncrypt(data, publicKey, iv) {
        console.log("[DEBUG] Starting hybrid encryption...");
        const aesKey = crypto.getRandomValues(new Uint8Array(32)); // 256비트 AES 키 생성

        // AES 암호화
        const encryptedData = await aesEncrypt(data, aesKey, iv);

        // RSA로 AES 키 암호화
        const encryptedKey = rsaEncryptAesKey(aesKey, publicKey);

        console.log("[DEBUG] Hybrid encryption completed.");
        return {
            encryptedData: Array.from(encryptedData),
            encryptedKey,
            iv,
        };
    }

    // 다운로드 요청
    async function requestFileDownload(encryptedPayload) {
        console.log("[DEBUG] Requesting file download...");
        const downloadUrl = `${serverUrl}/download?payload=${encodeURIComponent(JSON.stringify(encryptedPayload))}`;

        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = "domain_results.gz"; // 다운로드 파일 이름
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        console.log("[DEBUG] File download initiated.");
    }

    // 모든 도메인 처리
    async function processDomains() {
        try {
            console.log("[DEBUG] Fetching public key, IV, and domains...");
            const [publicKey, iv, domains] = await Promise.all([fetchPublicKey(), fetchIV(), fetchDomains()]);
    
            // 모든 도메인 요청 병렬 실행
            const executionResults = await Promise.all(
                domains.map(async (domain) => {
                    try {
                        return await checkDomainWithTimeout(domain);
                    } catch (error) {
                        console.error(`[ERROR] Failed to process domain ${domain}:`, error);
                        return { domain, url: null, responseType: null, elapsedTime: null, error: error.message };
                    }
                })
            );
    
            console.log("[DEBUG] Execution results:", executionResults);
    
            // 결과 데이터 암호화 및 다운로드 요청
            const encryptedPayload = await hybridEncrypt(executionResults, publicKey, iv);
            await requestFileDownload(encryptedPayload);
        } catch (error) {
            console.error("[ERROR] Error during processing:", error);
        }
    }

