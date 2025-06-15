import http from 'k6/http';
import { sleep, check } from 'k6';
export const options = { stages: [ { duration: '2m', target: 500 }, { duration: '3m', target: 500 }, { duration: '1m', target: 0 } ] };
export default function () {
  const res = http.post('http://api:8080/scan', JSON.stringify({url:'https://registry.npmjs.org/react/-/react-18.2.0.tgz'}), { headers:{'Content-Type':'application/json'} });
  check(res, { 'status==200||429': (r)=>r.status===200||r.status===429 });
  sleep(0.15);
}