'use strict';
window.WindscribeLocations=class {
  constructor({call,onConnected,getState}){
    this.call=call;this.onConnected=onConnected;this.getState=getState;this.account=null;this.data=null;this.attempted=null;this.loading=false;this.connecting=false;this.availability={};
    this.card=document.querySelector('#windscribe-location-card');this.list=document.querySelector('#windscribe-locations');
    this.country=document.querySelector('#windscribe-location-country');this.search=document.querySelector('#windscribe-location-search');this.mode=document.querySelector('#windscribe-location-protocol');this.port=document.querySelector('#windscribe-location-port');
    this.onlyAvailable=document.querySelector('#windscribe-location-available');this.message=document.querySelector('#windscribe-location-message');this.error=document.querySelector('#windscribe-location-error');
    document.querySelector('#windscribe-location-refresh').addEventListener('click',()=>this.load(true));
    for(const field of [this.country,this.search,this.onlyAvailable])field.addEventListener('input',()=>this.render());
    this.mode.addEventListener('change',()=>{this.fillPorts();this.render();});
  }
  updateAccount(account){
    this.account=account;this.card.hidden=!account?.loggedIn;
    if(!account?.loggedIn){this.data=null;this.attempted=null;this.list.replaceChildren();this.error.textContent='';return;}
    if(!account.busy&&!this.loading&&this.attempted!==account.profile?.username)this.load();
    this.render();
  }
  async load(force=false){
    if(this.loading||this.connecting||!this.account?.loggedIn)return;
    this.loading=true;this.attempted=this.account.profile.username;this.error.textContent='';this.render();
    const accountName=this.attempted;
    try{
      const [data,availability]=await Promise.all([this.call('windscribeLocations',{force}),this.call('windscribeInfo')]);
      if(!this.account?.loggedIn||this.account.profile.username!==accountName)return;
      this.data=data;this.availability=availability;this.fillControls();
    }catch(error){if(this.account?.loggedIn)this.error.textContent=error.message;}
    finally{this.loading=false;this.render();}
  }
  fillControls(){
    const previousCountry=this.country.value;this.country.replaceChildren(new Option('همهٔ کشورها و ناحیه‌ها',''));
    for(const value of [...new Set(this.data.locations.map(x=>x.country))].sort((a,b)=>a.localeCompare(b)))this.country.add(new Option(value,value));
    if([...this.country.options].some(x=>x.value===previousCountry))this.country.value=previousCountry;
    const labels={wireguard:'WireGuard',udp:'OpenVPN · UDP',tcp:'OpenVPN · TCP',ikev2:'IKEv2',stealth:'Stealth',wstunnel:'WStunnel'};
    const previousMode=this.mode.value||'wireguard';this.mode.replaceChildren();
    for(const [mode,label] of Object.entries(labels)){const option=new Option(label,mode);option.disabled=!this.data.ports[mode]?.length||this.availability[mode]===false;this.mode.add(option);}
    this.mode.value=[...this.mode.options].some(x=>x.value===previousMode&&!x.disabled)?previousMode:[...this.mode.options].find(x=>!x.disabled)?.value||'';
    this.fillPorts();
  }
  fillPorts(){const old=Number(this.port.value);this.port.replaceChildren();for(const port of this.data?.ports[this.mode.value]||[])this.port.add(new Option(String(port),String(port)));if([...this.port.options].some(x=>Number(x.value)===old))this.port.value=String(old);}
  render(){
    if(!this.account?.loggedIn)return;
    const pending=this.loading||this.connecting||this.account.busy||this.getState()?.status==='connecting'||this.getState()?.status==='disconnecting';
    for(const field of [this.country,this.search,this.mode,this.port,this.onlyAvailable,document.querySelector('#windscribe-location-refresh')])field.disabled=pending;
    if(this.loading){this.message.textContent='در حال دریافت موقعیت‌ها و سرورهای حساب…';return;}
    if(this.connecting){this.message.textContent='در حال آماده‌سازی و اتصال به سرور انتخاب‌شده…';for(const button of this.list.querySelectorAll('button'))button.disabled=true;return;}
    if(!this.data){this.message.textContent='برای دریافت فهرست، «تازه‌سازی سرورها» را بزنید.';return;}
    const query=this.search.value.trim().toLocaleLowerCase(),mode=this.mode.value,active=this.account.profile?.status===1;
    const rows=this.data.locations.filter(row=>(!this.country.value||row.country===this.country.value)&&(!query||[row.country,row.city,row.nickname,row.countryCode].join(' ').toLocaleLowerCase().includes(query))&&(!this.onlyAvailable.checked||active&&row.available&&row.protocols.includes(mode)));
    const ready=this.data.locations.filter(row=>active&&row.available&&row.protocols.includes(mode)).length;
    document.querySelector('#windscribe-count').textContent=new Intl.NumberFormat('fa-IR').format(ready)+' موقعیت';
    this.message.textContent=new Intl.NumberFormat('fa-IR').format(ready)+' موقعیت قابل اتصال · '+new Intl.NumberFormat('fa-IR').format(rows.length)+' نتیجه';
    this.list.replaceChildren();
    if(!rows.length){const text=document.createElement('p');text.textContent='موقعیتی با این جست‌وجو و پروتکل پیدا نشد.';this.list.append(text);return;}
    for(const row of rows){
      const item=document.createElement('div');item.className='windscribe-location';
      const details=document.createElement('div'),title=document.createElement('strong'),caption=document.createElement('small');
      title.dir='auto';title.style.textAlign='right';title.textContent=row.country+' · '+row.city+' — '+row.nickname;
      const allowed=active&&row.available&&row.protocols.includes(mode);
      caption.textContent=allowed?new Intl.NumberFormat('fa-IR').format(row.nodeCount)+' سرور'+(row.load==null?'':' · بار شبکه '+new Intl.NumberFormat('fa-IR').format(row.load)+'٪'):row.nodeCount?'این موقعیت یا پروتکل فعلاً آماده نیست':row.premium?'در اشتراک فعلی در دسترس نیست':'سرور قابل استفاده در حساب پیدا نشد';
      details.append(title,caption);
      const button=document.createElement('button');button.type='button';button.className='button secondary';button.textContent='اتصال';button.disabled=pending||!allowed;button.dataset.locationId=row.id;
      button.addEventListener('click',()=>this.connect(row.id));item.append(details,button);this.list.append(item);
    }
  }
  async connect(locationId){
    if(this.connecting||this.loading)return;
    const input={locationId,protocol:this.mode.value,port:Number(this.port.value)};
    this.connecting=true;this.error.textContent='';this.render();
    try{await this.call('windscribeConnect',input);await this.onConnected();}
    catch(error){this.error.textContent=error.message;}
    finally{this.connecting=false;this.render();}
  }
};
