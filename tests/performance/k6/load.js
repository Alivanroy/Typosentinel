import http from 'k6/http';
import { check, sleep } from 'k6';
export const options = { vus: 50, duration: '5m', thresholds: { http_req_failed: ['rate<0.005'], http_req_duration: ['p(95)<1200'] } };
export default function () {
  const res = http.post('http://api:8080/scan', JSON.stringify({url:'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz'}), { headers:{'Content-Type':'application/json'} });
  check(res, { 'status==200': (r)=>r.status===200 });
  sleep(0.1);
}