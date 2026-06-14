import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.ODO_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_API_KEY = __ENV.APP_ADMIN_API_KEY || 'devsecret';
const IDLE_SESSIONS = Number(__ENV.IDLE_SESSIONS || 1000);
const DURATION = __ENV.DURATION || '10m';
const TEST_USERNAME = __ENV.TEST_USERNAME || '';
const TEST_PASSWORD = __ENV.TEST_PASSWORD || '';

export const options = {
  scenarios: {
    idle_sessions: {
      executor: 'constant-vus',
      vus: IDLE_SESSIONS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.10'],
    http_req_duration: ['p(95)<1500'],
  },
};

function loginIfConfigured() {
  if (!TEST_USERNAME || !TEST_PASSWORD) {
    return false;
  }
  const res = http.post(`${BASE_URL}/login`, {
    username: TEST_USERNAME,
    password: TEST_PASSWORD,
    next: '/resources',
  }, { redirects: 0 });
  check(res, { 'login accepted or redirected': r => r.status === 302 || r.status === 303 });
  return res.status === 302 || res.status === 303;
}

export default function () {
  const loggedIn = loginIfConfigured();
  sleep(Math.random() * 5 + 1);

  const path = loggedIn ? '/resources' : '/api/v1/health';
  for (let i = 0; i < 3; i += 1) {
    const res = http.get(`${BASE_URL}${path}`);
    check(res, { 'lightweight keepalive succeeded': r => r.status === 200 || r.status === 302 });

    const runtime = http.get(`${BASE_URL}/api/v1/system/runtime`, {
      headers: { Authorization: `Bearer ${ADMIN_API_KEY}` },
    });
    check(runtime, { 'runtime metrics available': r => r.status === 200 });

    sleep(Math.random() * 60 + 30);
  }
}
