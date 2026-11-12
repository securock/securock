(async()=>{
 const {chromium}=require('playwright');
 const target=process.argv[1],origin=new URL(target).origin;
 const browser=await chromium.launch({headless:true,executablePath:process.env.SECUROCK_CHROMIUM_PATH||undefined});
 const findings=[];let blocked=0,requests=0;
 const headers={};if(process.argv[2]){const token=process.env[process.argv[2]];if(!token)throw Error('missing token');headers.Authorization='Bearer '+token;}
 const context=await browser.newContext({serviceWorkers:'block',extraHTTPHeaders:headers});
 await context.route('**/*',route=>{const r=route.request();if(++requests>100 || new URL(r.url()).origin!==origin || !['GET','HEAD'].includes(r.method())){blocked++;return route.abort();}return route.continue();});
 await context.routeWebSocket('**/*',ws=>{blocked++;ws.close();});
 const page=await context.newPage();
 const response=await page.goto(target,{waitUntil:'domcontentloaded',timeout:15000});
 if(!response || !response.ok())throw Error('navigation incomplete');
 const insecure=await page.locator('form').evaluateAll(forms=>forms.filter(f=>new URL(f.action).protocol==='http:').length);
 if(insecure)findings.push({id:'dast:browser-insecure-form',severity:'high',title:'Rendered page contains HTTP form actions',subject:target,remediation:'Submit sensitive forms over HTTPS.'});
 if(blocked)findings.push({id:'dast:browser-incomplete',severity:'info',title:'Browser requests were blocked by scan scope',subject:target,detail:'Only same-origin GET/HEAD requests are allowed; cross-origin, mutating, WebSocket, or excess requests were blocked.'});
 await browser.close();process.stdout.write(JSON.stringify({tool:'dast',findings}));
})().catch(()=>process.exit(2));
