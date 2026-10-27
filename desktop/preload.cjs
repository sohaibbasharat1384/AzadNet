const { contextBridge, ipcRenderer } = require('electron');
const actions = new Set(['state','settings','sharing','setSharing','regenerateSharing','copySharing','importText','importUrl','refresh','remove','select','start','stop','test','speed','logs','traffic','openFile','saveLogs']);
contextBridge.exposeInMainWorld('azadnet', Object.freeze({
  call: (action, ...args) => { if (!actions.has(action)) throw new Error('Unknown action'); return ipcRenderer.invoke('azadnet', action, ...args); },
  on: fn => { const handler = (_e,event,payload) => fn(event,payload); ipcRenderer.on('azadnet-event',handler); return () => ipcRenderer.removeListener('azadnet-event',handler); }
}));
