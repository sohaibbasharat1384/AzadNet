'use strict';
const {spawnSync}=require('node:child_process');
const path=require('node:path');
const python=process.env.AZADNET_PYTHON || (process.platform==='win32'?'python':'python3');
const result=spawnSync(python,[path.join(__dirname,'package.py')],{stdio:'inherit',windowsHide:true});
process.exit(result.status||0);
