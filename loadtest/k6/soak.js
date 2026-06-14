import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.ODO_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_API_KEY = __ENV.APP_ADMIN_API_KEY || 'devsecret';
const RESOURCE = JSON.parse(open('../fake-vendor-resource.json'));
const SOAK_USERS = Number(__ENV.SOAK_USERS || 100);
const DURATION = __ENV.DURATION || '10m';

export const options = {
  scenarios: {
    soak: {
      executor: 'constant-vus',
      vus: SOAK_USERS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<2500'],
  },
};

function adminHeaders() {
  return { Authorization: `Bearer ${ADMIN_API_KEY}`, 'Content-Type': 'application/json' };
}

function proxyURL(path) {
  return `${BASE_URL}/odo?url=${encodeURIComponent(`http://127.0.0.1:9090${path}`)}`;
}

export function setup() {
  http.post(`${BASE_URL}/api/v1/resources`, JSON.stringify(RESOURCE), { headers: adminHeaders() });
}

export default function () {
  for (const path of ['/', '/section/science', '/article/123', '/api/search?q=soak', '/api/user/status']) {
    const res = http.get(proxyURL(path));
    check(res, { [`${path} ok`]: r => r.status === 200 || r.status === 302 });
    sleep(Math.random() * 4 + 1);
  }
}
