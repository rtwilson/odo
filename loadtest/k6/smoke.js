import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.ODO_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_API_KEY = __ENV.APP_ADMIN_API_KEY || 'devsecret';
const RESOURCE = JSON.parse(open('../fake-vendor-resource.json'));

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    http_req_failed: ['rate<0.05'],
  },
};

function headers() {
  return { Authorization: `Bearer ${ADMIN_API_KEY}`, 'Content-Type': 'application/json' };
}

function proxyURL(path) {
  return `${BASE_URL}/odo?url=${encodeURIComponent(`http://127.0.0.1:9090${path}`)}`;
}

export function setup() {
  http.post(`${BASE_URL}/api/v1/resources`, JSON.stringify(RESOURCE), { headers: headers() });
}

export default function () {
  const health = http.get(`${BASE_URL}/api/v1/health`);
  check(health, { 'health is 200': r => r.status === 200 });

  const admin = http.get(`${BASE_URL}/admin`);
  check(admin, { 'admin page is available': r => r.status === 200 });

  const page = http.get(proxyURL('/'));
  check(page, { 'proxied fake vendor page is 200': r => r.status === 200 });

  const redirect = http.get(proxyURL('/redirect-to-article'), { redirects: 0 });
  check(redirect, { 'proxied redirect is 302': r => r.status === 302 });
}
