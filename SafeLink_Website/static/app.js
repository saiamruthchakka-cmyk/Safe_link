document.querySelectorAll("[data-demo]").forEach(button=>button.addEventListener("click",()=>{
 const mode=button.dataset.demo;
 if(mode==="url"){const el=document.querySelector("#url");if(el)el.value="http://192.0.2.10/verify-account?urgent=1";}
 if(mode==="email"){const el=document.querySelector("#message");if(el)el.value="URGENT: Your account will be suspended immediately. Verify your password and OTP now. Click here: http://192.0.2.10/login";}
}));
document.querySelectorAll("form").forEach(form=>form.addEventListener("submit",()=>{const b=form.querySelector('button[type="submit"]');if(b && !form.action.includes("logout")){b.dataset.oldText=b.innerHTML;b.innerHTML="Working…";b.disabled=true;}}));
