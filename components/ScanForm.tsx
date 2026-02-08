
import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Loader2, Network, Globe, Radio, Box, Crosshair, History, ChevronRight, FileEdit, MapPin, UserCog, ChevronDown, ChevronUp, ShieldAlert, Zap, StopCircle, Trash2, Server, Database, Lock, Globe2 } from 'lucide-react';
import { performScan } from '../services/scanService';
import { ScanReport, AppConfig, ScanMode } from '../types';

interface ScanFormProps {
  onScanComplete: (report: ScanReport) => void;
  config: AppConfig;
  draft: { target: string; domainStr: string; portRange: string; assetName: string; securityLevel: string; location: string; evaluator: string };
  setDraft: React.Dispatch<React.SetStateAction<any>>;
  logs: {msg: string, type: 'info' | 'warn' | 'error' | 'success' | 'system'}[];
  setLogs: React.Dispatch<React.SetStateAction<{msg: string, type: 'info' | 'warn' | 'error' | 'success' | 'system'}[]>>;
}

const ScanForm: React.FC<ScanFormProps> = ({ onScanComplete, config, draft, setDraft, logs, setLogs }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanMode, setScanMode] = useState<ScanMode>(ScanMode.QUICK);
  const [enableBrute, setEnableBrute] = useState(false);
  const [bruteProtocols, setBruteProtocols] = useState<string[]>(['SSH', 'MySQL']);
  const [progress, setProgress] = useState(0);
  const [currentAction, setCurrentAction] = useState("");
  const [showHistoryPopup, setShowHistoryPopup] = useState(false);
  const [showMetadata, setShowMetadata] = useState(false);
  const [targetHistory, setTargetHistory] = useState<string[]>(() => {
    const saved = localStorage.getItem('netaudit_target_history');
    return saved ? JSON.parse(saved) : [];
  });
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef({ cancelled: false });
  const hideTimeoutRef = useRef<number | null>(null);
  const lastLogRef = useRef<string>("");

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, currentAction]);

  const addLog = (msg: string, type: 'info' | 'warn' | 'error' | 'success' | 'system' = 'info') => {
    setLogs(prev => [...prev, { msg, type }]);
  };

  const handleUpdateDraft = (key: string, value: string) => {
    setDraft((prev: any) => ({ ...prev, [key]: value }));
  };

  const handleClearLogs = () => {
    if (confirm('是否清空当前所有内核审计日志？')) {
      setLogs([]);
      localStorage.removeItem('netaudit_logs');
    }
  };

  const saveToHistory = (ip: string) => {
    if (!ip || ip.trim() === '') return;
    const cleanIP = ip.trim();
    const newHistory = [cleanIP, ...targetHistory.filter(h => h !== cleanIP)].slice(0, 5);
    setTargetHistory(newHistory);
    localStorage.setItem('netaudit_target_history', JSON.stringify(newHistory));
  };

  const handleStopScan = () => {
    if (confirm('确认强制中止当前的审计作业吗？')) {
      abortRef.current.cancelled = true;
    }
  };

  const handleMouseEnter = () => {
    if (hideTimeoutRef.current) window.clearTimeout(hideTimeoutRef.current);
    setShowHistoryPopup(true);
  };

  const handleMouseLeave = () => {
    hideTimeoutRef.current = window.setTimeout(() => {
      setShowHistoryPopup(false);
    }, 150);
  };

  const toggleBruteProtocol = (proto: string) => {
    setBruteProtocols(prev => 
      prev.includes(proto) ? prev.filter(p => p !== proto) : [...prev, proto]
    );
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;
    
    saveToHistory(draft.target);
    setIsScanning(true);
    setProgress(0);
    setCurrentAction("正在校准审计引擎...");
    abortRef.current.cancelled = false;
    lastLogRef.current = "";

    const domains = draft.domainStr.split(',').map(d => d.trim()).filter(d => d);
    
    const metadata = {
        assetName: draft.assetName.trim() !== '' ? draft.assetName : `${config.defaultMetadata.assetNamePrefix}${draft.target}`,
        securityLevel: draft.securityLevel !== '' ? draft.securityLevel : config.defaultMetadata.securityLevel,
        location: draft.location.trim() !== '' ? draft.location : config.defaultMetadata.location,
        evaluator: draft.evaluator.trim() !== '' ? draft.evaluator : config.defaultMetadata.evaluator
    };

    const startTime = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    addLog(`---------------- SESSION START [${startTime}] ----------------`, 'system');
    addLog(`KERNEL: 初始化审计内核 v3.2...`, 'info');
    addLog(`ASSET: ${metadata.assetName} | LEVEL: ${metadata.securityLevel}`, 'info');
    addLog(`TARGET: ${draft.target}`, 'info');
    
    if (enableBrute) {
      addLog(`BRUTE: 已启用弱口令爆破 [${bruteProtocols.join(', ')}]`, 'warn');
    }
    
    try {
      const report = await performScan(
        config.apiBaseUrl, 
        draft.target, 
        draft.portRange, 
        config.ports, 
        config.dictionaries, 
        domains,
        scanMode,
        enableBrute,
        bruteProtocols,
        (pct, log) => {
          setProgress(pct);
          setCurrentAction(log);
          
          // 核心修改：移除百分比限制，实时显示不重复的日志
          if (log && log !== lastLogRef.current) {
            lastLogRef.current = log;
            
            // 简单的日志类型自动推断
            let type: 'info' | 'warn' | 'error' | 'success' | 'system' = 'info';
            if (log.includes('[+]') || log.includes('Success')) type = 'success';
            else if (log.includes('[!]') || log.includes('Refused') || log.includes('Error') || log.includes('Vulnerability')) type = 'warn';
            else if (log.includes('[-]')) type = 'info';
            else if (log.includes('[*]')) type = 'info';
            
            addLog(log, type);
          }
        },
        abortRef.current,
        metadata
      );

      setProgress(100);
      setCurrentAction("审计完成");
      addLog(`NETWORK: 审计作业结束，发现活动向量。`, 'success');
      
      setTimeout(() => {
        onScanComplete(report);
        setIsScanning(false);
      }, 1000);
    } catch (err: any) {
      addLog(`ENGINE: ${err.message}`, 'error');
      setIsScanning(false);
      setProgress(0);
      setCurrentAction("");
    }
  };

  const getLogColor = (type: string) => {
    switch(type) {
      case 'success': return 'text-brand';
      case 'warn': return 'text-orange-400';
      case 'error': return 'text-danger animate-pulse font-black';
      case 'system': return 'text-white/30 border-y border-white/5 py-1 my-2 block w-full text-center tracking-[0.3em]';
      default: return 'text-white/60';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-stretch animate-in slide-in-from-bottom-12 duration-1000">
      {/* 左侧配置面板 - 固定高度 */}
      <div className="lg:col-span-5 h-[750px]">
        <div className="tactical-card p-1 bg-gradient-to-br from-white/10 to-transparent rounded-[2.5rem] shadow-2xl h-full">
          <div className="bg-obsidian/95 rounded-[2.4rem] p-8 h-full flex flex-col justify-between overflow-y-auto custom-scrollbar">
            <div className="space-y-6">
              {/* Header */}
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 bg-brand text-black rounded-2xl flex items-center justify-center shadow-[0_0_20px_rgba(204,255,0,0.3)] transform rotate-2">
                  <Crosshair size={28} strokeWidth={2.5} />
                </div>
                <div>
                  <h2 className="text-2xl font-black italic uppercase leading-none tracking-tighter text-white">审计部署</h2>
                  <p className="text-[8px] font-black uppercase tracking-[0.3em] text-white/30 mt-1.5">NETWORK AUDIT DEPLOYMENT</p>
                </div>
              </div>

              {/* Form Fields */}
              <div className="space-y-4">
                {/* 目标 IP */}
                <div className="relative group" onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>
                  <label className="text-[9px] font-black uppercase tracking-[0.3em] text-white/20 mb-1.5 px-1 block">目标 IP 地址</label>
                  <div className="relative">
                    <input 
                      value={draft.target} 
                      onChange={e => handleUpdateDraft('target', e.target.value)} 
                      disabled={isScanning} 
                      className="w-full pl-11 pr-6 py-3.5 bg-white/[0.03] border border-white/10 rounded-xl text-white font-bold mono focus:border-brand/50 outline-none transition-all placeholder:text-white/10"
                      placeholder="127.0.0.1" 
                    />
                    <Network className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20 group-hover:text-brand transition-colors" size={16} />
                    
                    {/* 历史记录悬浮窗 */}
                    {showHistoryPopup && targetHistory.length > 0 && (
                      <div className="absolute top-full left-0 w-full mt-2 bg-black/90 border border-white/10 rounded-xl p-2 z-50 backdrop-blur-xl shadow-2xl animate-in fade-in slide-in-from-top-2">
                         <div className="flex items-center gap-2 px-3 py-2 text-[8px] font-black uppercase text-white/20 border-b border-white/5 mb-1">
                           <History size={10} /> 最近目标
                         </div>
                         {targetHistory.map((ip, idx) => (
                           <div 
                             key={idx} 
                             onClick={() => handleUpdateDraft('target', ip)}
                             className="px-3 py-2 hover:bg-white/10 rounded-lg cursor-pointer text-xs font-mono text-white/60 hover:text-brand transition-colors flex justify-between items-center group/item"
                           >
                             {ip}
                             <ChevronRight size={12} className="opacity-0 group-hover/item:opacity-100 transition-opacity" />
                           </div>
                         ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* 关联域名 */}
                <div>
                  <label className="text-[9px] font-black uppercase tracking-[0.3em] text-white/20 mb-1.5 px-1 block">关联域名 (VHost)</label>
                  <div className="relative group">
                    <input 
                      value={draft.domainStr} 
                      onChange={e => handleUpdateDraft('domainStr', e.target.value)} 
                      disabled={isScanning} 
                      className="w-full pl-11 pr-6 py-3.5 bg-white/[0.03] border border-white/10 rounded-xl text-white font-bold mono focus:border-brand/50 outline-none transition-all placeholder:text-white/10"
                      placeholder="example.com, api.site.org" 
                    />
                    <Globe className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20 group-hover:text-brand transition-colors" size={16} />
                  </div>
                </div>

                {/* 端口配置 */}
                <div>
                  <label className="text-[9px] font-black uppercase tracking-[0.3em] text-white/20 mb-1.5 px-1 block">端口扫描范围</label>
                  <div className="relative group">
                    <input 
                      value={draft.portRange} 
                      onChange={e => handleUpdateDraft('portRange', e.target.value)} 
                      disabled={isScanning} 
                      className="w-full pl-11 pr-6 py-3.5 bg-white/[0.03] border border-white/10 rounded-xl text-white font-bold mono focus:border-brand/50 outline-none transition-all placeholder:text-white/10 truncate"
                    />
                    <Radio className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20 group-hover:text-brand transition-colors" size={16} />
                  </div>
                </div>

                {/* 高级信息折叠 */}
                <div className="pt-2">
                   <button 
                     type="button"
                     onClick={() => setShowMetadata(!showMetadata)}
                     className="flex items-center gap-2 text-[9px] font-black uppercase text-white/30 hover:text-white transition-colors tracking-widest"
                   >
                     {showMetadata ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                     资产画像元数据 (Metadata)
                   </button>
                   
                   {showMetadata && (
                     <div className="grid grid-cols-2 gap-3 mt-3 animate-in slide-in-from-top-2">
                        <div className="relative">
                           <input value={draft.assetName} onChange={e => handleUpdateDraft('assetName', e.target.value)} placeholder="资产名称" className="w-full pl-8 pr-3 py-2 bg-white/[0.02] border border-white/5 rounded-lg text-xs text-white focus:border-white/20 outline-none" />
                           <Box size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
                        </div>
                        <div className="relative">
                           <input value={draft.securityLevel} onChange={e => handleUpdateDraft('securityLevel', e.target.value)} placeholder="等保等级" className="w-full pl-8 pr-3 py-2 bg-white/[0.02] border border-white/5 rounded-lg text-xs text-white focus:border-white/20 outline-none" />
                           <ShieldAlert size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
                        </div>
                        <div className="relative">
                           <input value={draft.location} onChange={e => handleUpdateDraft('location', e.target.value)} placeholder="物理位置" className="w-full pl-8 pr-3 py-2 bg-white/[0.02] border border-white/5 rounded-lg text-xs text-white focus:border-white/20 outline-none" />
                           <MapPin size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
                        </div>
                        <div className="relative">
                           <input value={draft.evaluator} onChange={e => handleUpdateDraft('evaluator', e.target.value)} placeholder="审计负责人" className="w-full pl-8 pr-3 py-2 bg-white/[0.02] border border-white/5 rounded-lg text-xs text-white focus:border-white/20 outline-none" />
                           <UserCog size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
                        </div>
                     </div>
                   )}
                </div>

                <div className="h-px bg-white/5 my-2"></div>

                {/* 扫描模式 */}
                <div className="grid grid-cols-2 gap-4">
                   <div 
                     onClick={() => !isScanning && setScanMode(ScanMode.QUICK)}
                     className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col gap-2 ${scanMode === ScanMode.QUICK ? 'bg-white/10 border-white/20' : 'bg-transparent border-white/5 hover:bg-white/5'}`}
                   >
                      <div className="flex justify-between items-center">
                         <span className={`text-[10px] font-black uppercase tracking-widest ${scanMode === ScanMode.QUICK ? 'text-white' : 'text-white/40'}`}>快速探测</span>
                         {scanMode === ScanMode.QUICK && <div className="w-2 h-2 rounded-full bg-brand"></div>}
                      </div>
                      <p className="text-[9px] text-white/30 leading-relaxed">仅进行端口存活探测与基础指纹识别，无侵入性。</p>
                   </div>
                   <div 
                     onClick={() => !isScanning && setScanMode(ScanMode.DEEP)}
                     className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col gap-2 ${scanMode === ScanMode.DEEP ? 'bg-danger/10 border-danger/40' : 'bg-transparent border-white/5 hover:bg-white/5'}`}
                   >
                      <div className="flex justify-between items-center">
                         <span className={`text-[10px] font-black uppercase tracking-widest ${scanMode === ScanMode.DEEP ? 'text-danger' : 'text-white/40'}`}>深度审计</span>
                         {scanMode === ScanMode.DEEP && <div className="w-2 h-2 rounded-full bg-danger animate-pulse"></div>}
                      </div>
                      <p className="text-[9px] text-white/30 leading-relaxed">执行全量漏洞脚本及弱口令检测，耗时较长。</p>
                   </div>
                </div>

                {/* 弱口令爆破开关与协议选择 */}
                {scanMode === ScanMode.DEEP && (
                  <div className="space-y-4">
                    <div 
                      onClick={() => !isScanning && setEnableBrute(!enableBrute)}
                      className={`flex items-center justify-between p-4 rounded-xl border cursor-pointer transition-all ${enableBrute ? 'bg-orange-500/10 border-orange-500/30' : 'bg-white/[0.02] border-white/5'}`}
                    >
                      <div className="flex items-center gap-3">
                         <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${enableBrute ? 'bg-orange-500 text-black' : 'bg-white/5 text-white/20'}`}>
                           <Terminal size={16} />
                         </div>
                         <div>
                            <div className={`text-xs font-black uppercase ${enableBrute ? 'text-orange-500' : 'text-white/40'}`}>弱口令爆破模块</div>
                            <div className="text-[8px] font-bold text-white/20 mt-0.5">字典攻击 (Brute-Force)</div>
                         </div>
                      </div>
                      <div className={`w-10 h-5 rounded-full relative transition-colors ${enableBrute ? 'bg-orange-500' : 'bg-white/10'}`}>
                         <div className={`absolute top-1 w-3 h-3 rounded-full bg-white transition-all shadow-sm ${enableBrute ? 'left-6' : 'left-1'}`}></div>
                      </div>
                    </div>
                    
                    {/* 协议选择矩阵 */}
                    {enableBrute && (
                      <div className="flex items-center gap-4 px-3 py-2 animate-in slide-in-from-top-2 bg-white/[0.02] border border-white/5 rounded-xl">
                         <span className="text-[9px] font-bold text-white/30 uppercase tracking-wide shrink-0">目标协议:</span>
                         <div className="flex flex-wrap gap-2">
                           {['SSH', 'MySQL'].map(proto => (
                             <button
                               key={proto}
                               type="button"
                               onClick={() => !isScanning && toggleBruteProtocol(proto)}
                               className={`px-3 py-1.5 rounded-lg border text-[9px] font-black uppercase transition-all flex items-center gap-2 ${
                                 bruteProtocols.includes(proto)
                                 ? 'bg-orange-500 text-black border-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.3)]'
                                 : 'bg-white/5 text-white/30 border-white/10 hover:border-white/20'
                               }`}
                             >
                               {bruteProtocols.includes(proto) && <div className="w-1.5 h-1.5 rounded-full bg-black"></div>}
                               {proto}
                             </button>
                           ))}
                         </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Action Button */}
            <button
              onClick={isScanning ? handleStopScan : handleScan}
              disabled={false}
              className={`w-full py-6 rounded-2xl flex items-center justify-center gap-3 text-sm font-black uppercase italic tracking-wider transition-all shadow-lg hover:shadow-xl active:scale-[0.98] ${
                isScanning 
                  ? 'bg-danger text-white shadow-danger/20 hover:bg-red-600' 
                  : 'bg-brand text-black shadow-brand/20 hover:bg-brand/90'
              }`}
            >
              {isScanning ? (
                <>
                  <StopCircle size={18} className="animate-pulse" />
                  中止审计作业
                </>
              ) : (
                <>
                  <Play size={18} fill="currentColor" />
                  立即执行审计
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* 右侧日志终端 - 自适应宽度 */}
      <div className="lg:col-span-7 h-[750px]">
        <div className="tactical-card rounded-[2.5rem] bg-black border border-white/10 h-full flex flex-col overflow-hidden shadow-2xl relative">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-brand via-white to-brand opacity-20"></div>
          
          {/* Terminal Header */}
          <div className="px-6 py-4 border-b border-white/10 flex justify-between items-center bg-white/[0.02]">
             <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                   <div className="w-2.5 h-2.5 rounded-full bg-red-500/50"></div>
                   <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50"></div>
                   <div className="w-2.5 h-2.5 rounded-full bg-green-500/50"></div>
                </div>
                <span className="text-[10px] font-mono text-white/40 ml-2">root@netaudit-kernel:~# scan_engine_v3.2</span>
             </div>
             <button onClick={handleClearLogs} className="text-white/20 hover:text-white transition-colors">
                <Trash2 size={14} />
             </button>
          </div>

          {/* Progress Bar Area */}
          {isScanning && (
            <div className="px-6 pt-6 pb-2">
               <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-brand mb-2">
                  <span>Task Progress</span>
                  <span>{progress}%</span>
               </div>
               <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-brand shadow-[0_0_15px_rgba(204,255,0,0.5)] transition-all duration-300 ease-out" 
                    style={{ width: `${progress}%` }}
                  ></div>
               </div>
               <div className="mt-2 text-[10px] font-mono text-white/50 truncate flex items-center gap-2">
                  <Loader2 size={10} className="animate-spin" />
                  {currentAction}
               </div>
            </div>
          )}

          {/* Console Logs */}
          <div 
            ref={scrollRef}
            className="flex-1 p-6 overflow-y-auto font-mono text-xs space-y-2 custom-scrollbar scroll-smooth"
          >
            {logs.length === 0 && (
               <div className="h-full flex flex-col items-center justify-center opacity-20 select-none">
                  <Terminal size={48} className="mb-4" />
                  <p className="uppercase tracking-[0.3em] font-black text-[10px]">系统日志待机中</p>
               </div>
            )}
            {logs.map((log, i) => (
              <div key={i} className={`leading-relaxed break-all ${getLogColor(log.type)} animate-in fade-in slide-in-from-left-2 duration-300`}>
                <span className="opacity-30 mr-3">[{new Date().toLocaleTimeString('zh-CN', { hour12: false })}]</span>
                {log.msg}
              </div>
            ))}
            {isScanning && (
               <div className="h-4 w-2 bg-brand animate-pulse inline-block align-middle ml-1"></div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanForm;
