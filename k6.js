import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Кастомные метрики
const authSuccessRate = new Rate('auth_success_rate');
const tokenVerificationRate = new Rate('token_verification_rate');
const authDuration = new Trend('auth_duration');
const verificationDuration = new Trend('verification_duration');

export const options = {
  stages: [
    { duration: '30s', target: 1000 },
    { duration: '1m', target: 1000 },
    { duration: '30s', target: 2000 },
    { duration: '1m', target: 2000 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.05'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const USER_PREFIX = __ENV.USER_PREFIX || 'test_user';
const DEVICE_PREFIX = __ENV.DEVICE_PREFIX || 'test_device';

function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateUserData(vuId) {
  const userSuffix = vuId + '_' + generateRandomString(6);
  return {
    user: `${USER_PREFIX}_${userSuffix}`,
    device: `${DEVICE_PREFIX}_${userSuffix}`,
    ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    country: ['US', 'RU', 'DE', 'FR', 'CN', 'JP', 'BR', 'IN'][Math.floor(Math.random() * 8)]
  };
}

export function setup() {
  console.log('🚀 Starting load test for Dual Token Auth Service');
  console.log(`📊 Base URL: ${BASE_URL}`);
  return { startTime: new Date().toISOString() };
}

export default function(data) {
  const userData = generateUserData(__VU);
  
  const authStart = Date.now();
  const authPayload = JSON.stringify({
    user: userData.user,
    device: userData.device
  });
  
  const authParams = {
    headers: {
      'Content-Type': 'application/json',
      'X-Country-Code': userData.country,
    },
    tags: { endpoint: 'auth' }
  };
  
  const authResponse = http.post(`${BASE_URL}/auth`, authPayload, authParams);
  const authEnd = Date.now();
  
  const authSuccess = check(authResponse, {
    'auth status is 200': (r) => r.status === 200,
    'auth response has ljwt': (r) => r.json('ljwt') !== undefined,
    'auth response has user': (r) => r.json('user') === userData.user,
  });
  
  authSuccessRate.add(authSuccess);
  authDuration.add(authEnd - authStart);
  
  if (!authSuccess) {
    console.log(`❌ Auth failed: ${authResponse.status} - ${authResponse.body}`);
    return;
  }
  
  const ljwtToken = authResponse.json('ljwt');
  
  sleep(Math.random() * 2);
  
  const verifyStart = Date.now();
  const verifyParams = {
    headers: {
      'Authorization': `Bearer ${ljwtToken}`,
      'X-Device-ID': userData.device,
      'X-Country-Code': userData.country,
    },
    tags: { endpoint: 'protected_api' }
  };
  
  const verifyResponse = http.get(`${BASE_URL}/api/check`, verifyParams);
  const verifyEnd = Date.now();
  
  const verifySuccess = check(verifyResponse, {
    'verification status is 200': (r) => r.status === 200,
    'verification returns array': (r) => Array.isArray(r.json()),
  });
  
  tokenVerificationRate.add(verifySuccess);
  verificationDuration.add(verifyEnd - verifyStart);
  
  if (!verifySuccess) {
    console.log(`❌ Verification failed: ${verifyResponse.status} - ${verifyResponse.body}`);
    return;
  }
  
  const userInfoParams = {
    headers: {
      'Authorization': `Bearer ${ljwtToken}`,
      'X-Device-ID': userData.device,
      'X-Country-Code': userData.country,
    },
    tags: { endpoint: 'user_info' }
  };
  
  const userInfoResponse = http.get(`${BASE_URL}/api/user/info`, userInfoParams);
  
  check(userInfoResponse, {
    'user info status is 200': (r) => r.status === 200,
    'user info has correct user': (r) => r.json('user') === userData.user,
    'user info has device': (r) => r.json('device') === userData.device,
  });
  
  const gjwtListParams = {
    headers: {
      'Authorization': `Bearer ${ljwtToken}`,
      'X-Device-ID': userData.device,
      'X-Country-Code': userData.country,
    },
    tags: { endpoint: 'gjwt_list' }
  };
  
  const gjwtListResponse = http.get(`${BASE_URL}/api/gjwt/list`, gjwtListParams);
  
  check(gjwtListResponse, {
    'gjwt list status is 200': (r) => r.status === 200,
    'gjwt list has tokens array': (r) => Array.isArray(r.json('tokens')),
  });
  
  sleep(Math.random() * 3 + 1);
}

export function teardown(data) {
  console.log('🏁 Load test completed');
  console.log(`🕒 Test started at: ${data.startTime}`);
  console.log(`🕒 Test ended at: ${new Date().toISOString()}`);
}