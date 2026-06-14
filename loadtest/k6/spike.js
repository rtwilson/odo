import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.ODO_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_API_KEY = __ENV.APP_ADMIN_API_KEY || 'devsecret';
const RESOURCE = JSON.parse(open('../fake-vendor-resource.json'));

export const options = {
  scenarios: {
    spike: {
      executor: 'ramping-vus',
      stages: [
        { duration: __ENV.RAMP_UP || '30s', target: Number(__ENV.SPIKE_USERS || 500) },
        { duration: __ENV.HOLD || '1m', target: Number(__ENV.SPIKE_USERS || 500) },
        { duration: __ENV.RAMP_DOWN || '30s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.10'],
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
  const paths = ['/', '/section/science', '/article/123', '/api/search?q=spike', '/assets/app.js'];
  const path = paths[Math.floor(Math.random() * paths.length)];
  const res = http.get(proxyURL(path));
  check(res, { 'request completed': r => r.status === 200 || r.status === 302 });
  sleep(Math.random() * 2);
}
