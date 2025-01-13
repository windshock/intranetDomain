require('dotenv').config(); // dotenv 초기화
const axios = require('axios');

// AbuseIPDB API를 사용하여 IP 점수를 확인하는 함수
async function checkIPAbuseScore(ip) {
    const apiKey = process.env.ABUSEIPDB_API_KEY; // 환경 변수에서 API 키 가져오기
    const url = `https://api.abuseipdb.com/api/v2/check`;

    try {
        const response = await axios.get(url, {
            headers: {
                Key: apiKey,
                Accept: 'application/json',
            },
            params: {
                ipAddress: ip,
                maxAgeInDays: 90, // 최근 90일간의 데이터 확인
            },
        });

        const abuseScore = response.data.data.abuseConfidenceScore;
        console.log(`IP ${ip} has an abuse confidence score of ${abuseScore}%`);
        return abuseScore;
    } catch (error) {
        console.error(`Error fetching data for IP ${ip}:`, error.message);
        return null;
    }
}

// 모듈로 내보내기
module.exports = { checkIPAbuseScore };
