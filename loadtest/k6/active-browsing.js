import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.ODO_BASE_URL || 'http://127.0.0.1:8080';
const ADMIN_API_KEY = __ENV.APP_ADMIN_API_KEY || 'devsecret';
const RESOURCE = JSON.parse(open('../fake-vendor-resource.json'));
const ACTIVE_USERS = Number(__ENV.ACTIVE_USERS || 50);
const DURATION = __ENV.DURATION || '5m';

export const options = {
  scenarios: {
    active_browsing: {
      executor: 'constant-vus',
      vus: ACTIVE_USERS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<2000'],
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
  let res = http.get(proxyURL('/'));
  check(res, { 'home 200': r => r.status === 200 });
  sleep(Math.random() * 2 + 1);

  res = http.get(proxyURL('/section/science'));
  check(res, { 'section 200': r => r.status === 200 });
  sleep(Math.random() * 3 + 1);

  res = http.get(proxyURL('/article/123'));
  check(res, { 'article 200': r => r.status === 200 });
  sleep(Math.random() * 3 + 1);

  res = http.get(proxyURL('/api/search?q=test'));
  check(res, { 'search 200': r => r.status === 200 });

  res = http.get(proxyURL('/api/user/status'));
  check(res, { 'status api 200': r => r.status === 200 });

  res = http.get(proxyURL('/assets/app.css'));
  check(res, { 'css 200': r => r.status === 200 });

  res = http.get(proxyURL('/assets/app.js'));
  check(res, { 'js 200': r => r.status === 200 });

  res = http.get(proxyURL('/redirect-to-article'));
  check(res, { 'redirect lands on article': r => r.status === 200 });
  sleep(Math.random() * 4 + 1);
}
