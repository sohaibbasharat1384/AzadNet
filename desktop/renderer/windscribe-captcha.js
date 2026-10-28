'use strict';
// Displays provider challenges and forwards only the user's own interaction.
// It never identifies a target, generates a solution or synthesizes motion.
window.WindscribeCaptcha=class {
  constructor({submit,refresh}){
    this.submit=submit;this.refresh=refresh;this.challenge=null;this.key=null;this.position=0;this.trailX=[];this.trailY=[];this.zoom=1;this.busy=false;this.drag=null;this.loaded=false;
    this.dialog=document.querySelector('#windscribe-captcha-dialog');
    this.stage=document.querySelector('#windscribe-captcha-stage');this.viewport=document.querySelector('#windscribe-captcha-viewport');
    this.handle=document.querySelector('#windscribe-captcha-handle');this.piece=document.querySelector('#windscribe-captcha-piece');
    this.ascii=document.querySelector('#windscribe-account-ascii');this.answer=document.querySelector('#windscribe-account-answer');
    document.querySelector('#windscribe-captcha-open').addEventListener('click',()=>this.open());
    document.querySelector('#windscribe-captcha-close').addEventListener('click',()=>this.dialog.close());
    document.querySelector('#windscribe-captcha-fit').addEventListener('click',()=>{this.zoom=1;this.layout();});
    document.querySelector('#windscribe-captcha-larger').addEventListener('click',()=>{this.zoom=Math.min(3,this.zoom*1.25);this.layout();});
    document.querySelector('#windscribe-captcha-smaller').addEventListener('click',()=>{this.zoom=Math.max(.5,this.zoom/1.25);this.layout();});
    document.querySelector('#windscribe-captcha-refresh').addEventListener('click',()=>this.refresh(this.challenge?.captchaType||'image'));
    document.querySelector('#windscribe-captcha-switch').addEventListener('click',()=>this.refresh(this.challenge?.captchaType==='ascii'?'image':'ascii'));
    document.querySelector('#windscribe-captcha-form').addEventListener('submit',event=>{
      event.preventDefault();if(this.busy||this.challenge?.phase!=='captcha')return;
      if(this.challenge.captchaType==='image'){
        if(!this.trailX.length)return;
        this.submit({id:this.challenge.id,captchaSolution:String(Math.trunc(this.position)),captchaTrailX:[...this.trailX],captchaTrailY:[...this.trailY]});
      }else this.submit({id:this.challenge.id,captchaSolution:this.answer.value.trim()});
      this.answer.value='';
    });
    this.handle.addEventListener('pointerdown',event=>{
      if(this.busy||event.button!==0)return;
      this.drag={id:event.pointerId,clientX:event.clientX,position:this.position};this.handle.setPointerCapture(event.pointerId);event.preventDefault();
    });
    this.handle.addEventListener('pointermove',event=>{
      if(!this.drag||this.drag.id!==event.pointerId||this.busy)return;
      const scale=this.stage.getBoundingClientRect().width/this.challenge.image.background.width;
      this.move(this.drag.position+(event.clientX-this.drag.clientX)/scale);this.record(event.clientX,event.clientY);
    });
    const stop=()=>{this.drag=null;};this.handle.addEventListener('pointerup',stop);this.handle.addEventListener('pointercancel',stop);
    this.handle.addEventListener('keydown',event=>{
      if(this.busy||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
      event.preventDefault();const step=event.shiftKey?10:1;
      this.move(event.key==='Home'?0:event.key==='End'?this.max():this.position+(event.key==='ArrowRight'?step:-step));
      const rect=this.handle.getBoundingClientRect();this.record(rect.left+rect.width/2,rect.top+rect.height/2);
    });
    this.answer.addEventListener('input',()=>this.controls());
    new ResizeObserver(()=>{if(this.dialog.open)this.layout();}).observe(this.dialog);
  }
  max(){return this.challenge?.image?this.challenge.image.background.width-this.challenge.image.piece.width:0;}
  record(clientX,clientY){
    const rect=this.stage.getBoundingClientRect();this.trailX.push(clientX-rect.left);this.trailY.push(clientY-rect.top);
    if(this.trailX.length>50){this.trailX.shift();this.trailY.shift();}this.controls();
  }
  move(value){this.position=Math.max(0,Math.min(this.max(),value));this.draw();}
  draw(){
    if(!this.challenge?.image)return;
    const ratio=this.position/this.challenge.image.background.width;
    this.piece.style.left=(ratio*100)+'%';this.handle.style.left=(ratio*100)+'%';this.handle.setAttribute('aria-valuenow',String(Math.trunc(this.position)));
  }
  controls(){
    const ready=this.challenge?.phase==='captcha';const image=this.challenge?.captchaType==='image';
    document.querySelector('#windscribe-captcha-submit').disabled=this.busy||!ready||(image?(!this.loaded||!this.trailX.length):!this.answer.value.trim());
    for(const id of ['refresh','switch'])document.querySelector('#windscribe-captcha-'+id).disabled=this.busy;
    this.handle.disabled=this.busy||(image&&!this.loaded);this.answer.disabled=this.busy||!ready;
  }
  layout(){
    if(!this.challenge||!this.dialog.open)return;
    const available=Math.max(240,this.viewport.clientWidth-4);
    if(this.challenge.captchaType==='image'&&this.challenge.image){
      const image=this.challenge.image,base=Math.min(available,Math.max(image.background.width,Math.min(720,image.background.width*2)));
      this.stage.style.width=(base*this.zoom)+'px';
      this.piece.style.width=(image.piece.width/image.background.width*100)+'%';this.piece.style.top=(image.top/image.background.height*100)+'%';this.draw();
    }else{
      const lines=(this.challenge.asciiArt||'').split(/\r?\n/);const columns=Math.max(1,...lines.map(line=>line.replace(/\t/g,'        ').length));
      const font=Math.max(8,Math.min(17,(available-32)/(columns*.61)))*this.zoom;this.ascii.style.fontSize=font+'px';
    }
    document.querySelector('#windscribe-captcha-zoom-label').textContent=Math.round(this.zoom*100)+'%';
  }
  open(){if(!this.challenge||!['captcha','captcha-retry'].includes(this.challenge.phase))return;if(!this.dialog.open)this.dialog.showModal();this.layout();}
  render(challenge,busy){
    this.busy=busy;
    if(!challenge||!['captcha','captcha-retry'].includes(challenge.phase)){
      this.challenge=null;this.key=null;this.drag=null;this.trailX=[];this.trailY=[];this.answer.value='';this.ascii.textContent='';
      document.querySelector('#windscribe-captcha-background').removeAttribute('src');this.piece.removeAttribute('src');if(this.dialog.open)this.dialog.close();return;
    }
    this.challenge=challenge;const key=challenge.id+':'+challenge.captchaType+':'+challenge.phase;
    if(key!==this.key){
      this.key=key;this.position=0;this.trailX=[];this.trailY=[];this.drag=null;this.zoom=1;this.answer.value='';this.loaded=false;
      const image=challenge.captchaType==='image',ready=challenge.phase==='captcha';
      document.querySelector('#windscribe-captcha-image').hidden=!image||!ready;
      document.querySelector('#windscribe-captcha-ascii-wrap').hidden=image||!ready;
      document.querySelector('#windscribe-captcha-answer-label').hidden=image||!ready;
      document.querySelector('#windscribe-captcha-help').textContent=challenge.message||'';
      document.querySelector('#windscribe-captcha-switch').textContent=image?'نمایش متنی':'نمایش تصویری';
      this.answer.required=!image&&ready;this.ascii.textContent=challenge.asciiArt||'';
      if(image&&ready){
        const background=document.querySelector('#windscribe-captcha-background');
        const loaded=()=>{if(this.key!==key)return;this.loaded=background.complete&&background.naturalWidth>0&&this.piece.complete&&this.piece.naturalWidth>0;this.controls();};
        background.onload=loaded;this.piece.onload=loaded;background.src=challenge.image.background.src;this.piece.src=challenge.image.piece.src;
        this.handle.setAttribute('aria-valuemax',String(this.max()));
        const failed=()=>{if(this.key!==key)return;this.loaded=false;this.controls();document.querySelector('#windscribe-captcha-help').textContent='تصویر نمایش داده نشد؛ CAPTCHA تازه دریافت کنید یا نمایش متنی را انتخاب کنید.';};background.onerror=failed;this.piece.onerror=failed;
      }
      this.open();
    }
    this.controls();this.layout();
  }
};
