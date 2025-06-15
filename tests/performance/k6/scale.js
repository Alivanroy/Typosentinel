import http from 'k6/http';
import { sleep } from 'k6';
export const options = { stages: [ { duration:'5m', target:100 }, { duration:'10m', target:1000 }, { duration:'5m', target:100 } ] };
export default function(){ http.post('http://api:8080/scan', '{}'); sleep(0.2); }