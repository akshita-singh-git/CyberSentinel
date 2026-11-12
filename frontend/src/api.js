const BASE='/api/v1'
export function getToken(){return localStorage.getItem('cs_token')}
export async function api(path, options={}){
  const headers={'Content-Type':'application/json',...(options.headers||{})}
  if(getToken()) headers.Authorization=`Bearer ${getToken()}`
  const response=await fetch(`${BASE}${path}`,{...options,headers})
  if(!response.ok){let detail='Request failed';try{const payload=await response.json();const raw=payload?.detail??payload?.message??detail;
    detail=typeof raw==='string'?raw:JSON.stringify(raw)
  }catch{};throw new Error(detail)}
  const type=response.headers.get('content-type')||''
  return type.includes('application/json')?response.json():response.text()
}
