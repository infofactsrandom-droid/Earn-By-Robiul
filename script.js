const bubble = document.getElementById('bubble');
const panel = document.getElementById('panel');
const list = document.getElementById('list');
const toast = document.getElementById('toast');

/* === Bubble Drag === */
let offsetX, offsetY, dragging=false;

bubble.addEventListener('mousedown', e=>{
  dragging=true;
  offsetX = e.clientX - bubble.offsetLeft;
  offsetY = e.clientY - bubble.offsetTop;
  bubble.style.cursor="grabbing";
});

document.addEventListener('mousemove', e=>{
  if(!dragging) return;
  bubble.style.left=(e.clientX-offsetX)+"px";
  bubble.style.top=(e.clientY-offsetY)+"px";
  bubble.style.right="auto"; // reset right
  bubble.style.bottom="auto"; // reset bottom
});

document.addEventListener('mouseup', e=>{
  dragging=false;
  bubble.style.cursor="grab";
});

// Touch support
bubble.addEventListener('touchstart', e=>{
  dragging=true;
  const t=e.touches[0];
  offsetX = t.clientX - bubble.offsetLeft;
  offsetY = t.clientY - bubble.offsetTop;
});
document.addEventListener('touchmove', e=>{
  if(!dragging) return;
  const t=e.touches[0];
  bubble.style.left=(t.clientX-offsetX)+"px";
  bubble.style.top=(t.clientY-offsetY)+"px";
  bubble.style.right="auto";
  bubble.style.bottom="auto";
});
document.addEventListener('touchend', ()=>dragging=false);

/* === TOTP Utils === */
function base32ToBytes(b32){
  b32 = (b32||'').replace(/=+$/,'').toUpperCase().replace(/[^A-Z2-7]/g,'');
  if(!b32) return new Uint8Array(0);
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits=0,value=0,bytes=[];
  for(let i=0;i<b32.length;i++){
    const idx = alphabet.indexOf(b32[i]);
    if(idx===-1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if(bits>=8){bits-=8;bytes.push((value>>bits)&0xff);}
  }
  return new Uint8Array(bytes);
}
async function hmacSha1(keyBytes,data){
  const key = await crypto.subtle.importKey("raw",keyBytes,{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const sig = await crypto.subtle.sign("HMAC",key,data);
  return new Uint8Array(sig);
}
async function generateTOTP(secretBase32,{digits=6,period=30}={}){
  try{
    const key = base32ToBytes(secretBase32);
    if(key.length===0) throw new Error("Invalid secret");
    const epoch = Math.floor(Date.now()/1000);
    const counter = Math.floor(epoch/period);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0,Math.floor(counter/0x100000000));
    view.setUint32(4,counter%0x100000000);
    const hmac = await hmacSha1(key,buf);
    const offset = hmac[hmac.length-1]&0x0f;
    const code = ((hmac[offset]&0x7f)<<24)|((hmac[offset+1]&0xff)<<16)|((hmac[offset+2]&0xff)<<8)|(hmac[offset+3]&0xff);
    return (code%(10**digits)).toString().padStart(digits,'0');
  }catch(e){return 'ERR';}
}
function parseSecrets(text){return (text||'').split(/[\r\n,;]+/).map(s=>s.trim()).filter(Boolean);}
function showToast(msg,ms=2000){toast.textContent=msg;toast.style.display='block';setTimeout(()=>toast.style.display='none',ms);}
async function getClipboardSecret(){
  try{return await navigator.clipboard.readText();}
  catch(e){return prompt("Clipboard blocked! Secret দিন:");}
}

/* === Bubble Action === */
bubble.addEventListener('click', async ()=>{
  if(dragging) return; // drag করলে click ট্রিগার না হবে
  const text = await getClipboardSecret();
  if(!text){showToast("Secret পাওয়া যায়নি");return;}
  const secrets = parseSecrets(text);
  if(secrets.length===0){showToast("Valid secret নেই");return;}

  const codes=[];
  for(const s of secrets){codes.push(await generateTOTP(s));}
  await navigator.clipboard.writeText(codes.join('\n'));

  list.innerHTML='';
  secrets.forEach((s,i)=>{
    const div=document.createElement('div');
    div.className='totp-item';
    div.innerHTML=`<div class="secret">${s.length>18?s.slice(0,18)+'…':s}</div><div class="code">${codes[i]}</div>`;
    list.appendChild(div);
  });

  panel.style.display='block';
  showToast(codes.length===1?`Code copied: ${codes[0]}`:`${codes.length} কোড কপি হয়েছে`);
  setTimeout(()=>panel.style.display='none',4000);
});
