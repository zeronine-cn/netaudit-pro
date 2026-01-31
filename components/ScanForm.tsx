
import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Loader2, Network, Globe, Radio, Box, Crosshair, History, ChevronRight, FileEdit, MapPin, UserCog, ChevronDown, ChevronUp, ShieldAlert, Zap, StopCircle, Trash2 } from 'lucide-react';
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

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;
    
    saveToHistory(draft.target);
    setIsScanning(true);
    setProgress(0);
    setCurrentAction("正在校准审计引擎...");
    abortRef.current.cancelled = false;

    const domains = draft.domainStr.split(',').map(d => d.trim()).filter(d => d);
    
    const metadata = {
        assetName: draft.assetName.trim() !== '' ? draft.assetName : `${config.defaultMetadata.assetNamePrefix}${draft.target}`,
        securityLevel: draft.securityLevel !== '' ? draft.securityLevel : config.defaultMetadata.securityLevel,
        location: draft.location.trim() !== '' ? draft.location : config.defaultMetadata.location,
        evaluator: draft.evaluator.trim() !== '' ? draft.evaluator : config.defaultMetadata.evaluator
    };

    const startTime = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    addLog(`---------------- SESSION START [${startTime}] ----------------`, 'system');
    addLog(`KERNEL: 初始化审计内核 v3.1...`, 'info');
    addLog(`ASSET: ${metadata.assetName} | LEVEL: ${metadata.securityLevel}`, 'info');
    addLog(`TARGET: ${draft.target}`, 'info');
    
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
        (pct, log) => {
          setProgress(pct);
          setCurrentAction(log);
          if (pct > 0 && pct % 20 === 0 && pct < 100) {
            addLog(`[CORE] 审计进度已同步: ${pct}% - ${log}`, 'info');
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
                      className="w-full pl-11 pr-6 py-3.5 bg-white/[0.03] border border-white/10 rounded-xl text-sm font-bold focus:border-brand/40 outline-none transition-all mono text-white/90" 
                      placeholder="127.0.0.1" 
                    />
                    <Network className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20" size={16} />
                  </div>
                  {showHistoryPopup && targetHistory.length > 0 && !isScanning && (
                    <div className="absolute top-full left-0 w-full z-[100] pt-2">
                      <div className="bg-black/95 backdrop-blur-2xl border border-brand/20 rounded-2xl p-3 shadow-2xl">
                        {targetHistory.map((ip, idx) => (
                          <button key={idx} onClick={() => { handleUpdateDraft('target', ip); setShowHistoryPopup(false); }} className="w-full flex items-center justify-between px-4 py-2.5 rounded-xl hover:bg-brand hover:text-black transition-all group/item mb-1">
                            <span className="text-[10px] font-mono font-bold">{ip}</span>
                            <ChevronRight size={10} />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* 定级备案面板 */}
                <div className="border border-white/5 rounded-2xl overflow-hidden bg-white/[0.02]">
                  <button 
                    onClick={() => setShowMetadata(!showMetadata)}
                    className={`w-full px-4 py-3.5 flex items-center justify-between hover:bg-white/5 transition-all ${showMetadata ? 'bg-white/5' : ''}`}
                  >
                    <div className="flex items-center gap-2.5">
                      <FileEdit size={14} className="text-brand/60" />
                      <span className="text-[9px] font-black uppercase tracking-[0.2em] text-white/40 italic">测评对象画像</span>
                    </div>
                    {showMetadata ? <ChevronUp size={14} className="text-white/20" /> : <ChevronDown size={14} className="text-white/20" />}
                  </button>
                  {showMetadata && (
                    <div className="p-5 pt-1 space-y-4 animate-in slide-in-from-top-4 duration-300">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <label className="text-[8px] font-black uppercase text-white/20 tracking-widest block ml-1">资产名称</label>
                          <div className="relative">
                            <input value={draft.assetName} onChange={e => handleUpdateDraft('assetName', e.target.value)} className="w-full pl-8 py-2.5 bg-black/40 border border-white/10 rounded-lg text-[9px] font-bold text-white outline-none" placeholder="自动填充..." />
                            <Box className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/10" size={12} />
                          </div>
                        </div>
                        <div className="space-y-1">
                          <label className="text-[8px] font-black uppercase text-white/20 tracking-widest block ml-1">等保等级</label>
                          <select value={draft.securityLevel} onChange={e => handleUpdateDraft('securityLevel', e.target.value)} className="w-full px-3 py-2.5 bg-black/40 border border-white/10 rounded-lg text-[9px] font-bold text-brand outline-none appearance-none">
                            <option value="">跟随模板</option>
                            <option value="二级">等保二级 (L2)</option>
                            <option value="三级">等保三级 (L3)</option>
                          </select>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* 关联域名 */}
                <div className="relative group">
                  <label className="text-[9px] font-black uppercase tracking-[0.3em] text-white/20 mb-1.5 px-1 block">关联域名</label>
                  <div className="relative">
                    <textarea 
                      value={draft.domainStr} 
                      onChange={e => handleUpdateDraft('domainStr', e.target.value)} 
                      disabled={isScanning} 
                      rows={2} 
                      className="w-full pl-11 pr-6 py-3.5 bg-white/[0.03] border border-white/10 rounded-xl text-[11px] font-bold focus:border-brand/40 outline-none transition-all mono text-white/90 resize-none" 
                      placeholder="example.com" 
                    />
                    <Globe className="absolute left-4 top-4 text-white/20" size={16} />
                  </div>
                </div>

                {/* 审计深度 */}
                <div className="space-y-2">
                  <label className="text-[9px] font-black uppercase tracking-[0.3em] text-white/20 px-1 block">引擎深度</label>
                  <div className="grid grid-cols-2 gap-3">
                    {[ScanMode.QUICK, ScanMode.DEEP].map(mode => (
                      <button 
                        key={mode} 
                        onClick={() => setScanMode(mode)} 
                        className={`py-2.5 rounded-xl text-[9px] font-black uppercase italic tracking-widest border transition-all ${scanMode === mode ? 'bg-brand text-black border-brand shadow-[0_0_15px_rgba(204,255,0,0.2)]' : 'bg-white/5 text-white/30 border-white/10 hover:bg-white/10'}`}
                      >
                        {mode}
                      </button>
                    ))}
                  </div>
                </div>

                {/* 弱口令开关 */}
                <div className={`p-4 rounded-xl border transition-all flex items-center justify-between ${enableBrute ? 'bg-brand/5 border-brand/30' : 'bg-white/5 border-white/10'} ${scanMode === ScanMode.QUICK ? 'opacity-20 pointer-events-none' : 'cursor-pointer'}`} onClick={() => !isScanning && setEnableBrute(!enableBrute)}>
                  <div className="flex items-center gap-3">
                     <div className={`w-7 h-7 rounded-lg flex items-center justify-center transition-all ${enableBrute ? 'bg-brand text-black' : 'bg-white/10 text-white/30'}`}>
                        <ShieldAlert size={14} />
                     </div>
                     <div className="text-[9px] font-black text-white/80 uppercase">弱口令扫描</div>
                  </div>
                  <div className={`w-8 h-4 rounded-full relative transition-all ${enableBrute ? 'bg-brand' : 'bg-white/10'}`}>
                     <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${enableBrute ? 'left-4.5' : 'left-0.5'}`}></div>
                  </div>
                </div>

                {/* 端口范围 */}
                <div className="relative group">
                  <label className="text-[9px] font-black uppercase tracking-[0.3em] text-white/20 mb-1.5 px-1 block">探测端口集</label>
                  <div className="relative">
                    <input 
                      value={draft.portRange} 
                      onChange={e => handleUpdateDraft('portRange', e.target.value)} 
                      disabled={isScanning} 
                      className="w-full pl-11 pr-6 py-3.5 bg-white/[0.03] border border-white/10 rounded-xl text-sm font-bold focus:border-brand/40 outline-none transition-all mono text-white/90" 
                    />
                    <Radio className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20" size={16} />
                  </div>
                </div>
              </div>
            </div>

            {/* Submit */}
            <div className="pt-4">
              {isScanning ? (
                <button onClick={handleStopScan} className="w-full py-5 rounded-2xl text-md font-black uppercase italic flex items-center justify-center gap-4 bg-danger/20 text-danger border border-danger/40 hover:bg-danger hover:text-white transition-all">
                  <StopCircle size={20} />
                  <span>中止审计</span>
                </button>
              ) : (
                <button onClick={handleScan} className="w-full py-5 rounded-2xl text-md font-black uppercase italic flex items-center justify-center gap-4 bg-brand text-black hover:shadow-[0_0_30px_rgba(204,255,0,0.4)] transition-all">
                  <Play fill="currentColor" size={16} />
                  <span>开始审计</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 右侧日志面板 - 固定高度与内部滚动 */}
      <div className="lg:col-span-7 h-[750px]">
        <div className="tactical-card h-full flex flex-col overflow-hidden rounded-[2.5rem] border border-white/10 bg-obsidian/40 shadow-2xl relative">
          {/* Terminal Header */}
          <div className="px-8 py-4 border-b border-white/5 bg-white/[0.02] flex items-center justify-between shrink-0">
             <div className="flex items-center gap-3">
               <div className="w-1.5 h-1.5 rounded-full bg-brand animate-pulse"></div>
               <span className="font-black uppercase tracking-[0.4em] text-[9px] text-white/40 italic">引擎终端 (V3.1-STABLE)</span>
             </div>
             <button onClick={handleClearLogs} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-danger/20 hover:text-danger text-[8px] font-black uppercase tracking-widest transition-all text-white/20 border border-transparent hover:border-danger/20">
               <Trash2 size={10} /> 清除
             </button>
          </div>

          {/* Log Area - 核心滚动区 */}
          <div ref={scrollRef} className="p-8 font-mono text-[10px] flex-1 overflow-y-auto bg-black/60 custom-scrollbar scanline-container">
            {logs.length === 0 && !isScanning && (
              <div className="h-full flex flex-col items-center justify-center space-y-6 opacity-10">
                <Terminal size={48} strokeWidth={1} className="animate-pulse" />
                <span className="font-black uppercase tracking-[1.5em] text-xs">Waiting for Task</span>
              </div>
            )}
            
            <div className="space-y-2.5 pb-10">
              {logs.map((log, i) => (
                <div key={i} className={`flex gap-4 animate-in slide-in-from-left-4 duration-300 ${getLogColor(log.type)}`}>
                  {log.type !== 'system' && <span className="opacity-10 shrink-0 font-black text-[8px] pt-0.5">[{i.toString().padStart(3, '0')}]</span>}
                  <span className="leading-relaxed flex-1 break-all whitespace-pre-wrap">{log.msg}</span>
                </div>
              ))}
            </div>
          </div>

          {/* 进度条 - 固定在终端底部 */}
          {isScanning && (
            <div className="px-8 py-6 bg-brand/[0.02] border-t border-white/5 shrink-0 animate-in slide-in-from-bottom-4">
              <div className="flex justify-between items-center mb-4">
                <div className="flex items-center gap-3">
                  <Zap size={14} className="text-brand animate-pulse" />
                  <span className="text-[10px] font-black text-brand uppercase tracking-[0.2em] italic">内核作业中...</span>
                </div>
                <span className="text-[11px] font-mono text-brand font-black tracking-widest">{progress}%</span>
              </div>
              <div className="text-white/80 font-black text-[10px] mb-4 uppercase italic tracking-tight truncate">
                {currentAction}
              </div>
              <div className="h-2 bg-white/5 rounded-full overflow-hidden p-0.5 border border-white/5">
                <div className="h-full bg-brand shadow-[0_0_15px_#CCFF00] transition-all duration-500 rounded-full" style={{ width: `${progress}%` }}></div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanForm;
