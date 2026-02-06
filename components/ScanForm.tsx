
import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Loader2, Network, Globe, Radio, Box, Crosshair, History, ChevronRight, FileEdit, MapPin, UserCog, ChevronDown, ChevronUp, ShieldAlert, Zap, StopCircle, Trash2 } from 'lucide-react';
import { performScan } from '../services/scanService';
import { ScanReport, AppConfig, ScanMode } from '../types';

interface ScanFormProps {
  onScanComplete: (report: ScanReport) => void;
  config: AppConfig;
  draft: { target: string; domainStr: string; portRange: string; assetName: string; securityLevel: string; location: string; evaluator: string };
  setDraft: React.Dispatch<React.SetStateAction<any>>;
  logs: {msg: string, type: string, timestamp: string}[];
  setLogs: React.Dispatch<React.SetStateAction<{msg: string, type: string, timestamp: string}[]>>;
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
  const lastLogRef = useRef<string>(""); 

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, currentAction]);

  const getTimestamp = () => {
    const now = new Date();
    // 使用 HH:mm:ss 格式，不显示毫秒，保持整洁
    return now.toLocaleTimeString('en-GB', { hour12: false });
  };

  const addLog = (fullMsg: string, fallbackType: string = 'info') => {
    // 解析后端发来的 [PREFIX] 格式
    // 格式如: "[INFO] SCAN: Port 80 found"
    const regex = /^\[(INFO|WARN|ERROR|SUCCESS|FATAL)\]\s*(.*)/;
    const match = fullMsg.match(regex);
    
    let type = fallbackType;
    let msg = fullMsg;

    if (match) {
        type = match[1].toLowerCase(); // INFO -> info
        msg = match[2]; // 剥离前缀后的内容
    }

    setLogs(prev => [...prev, { msg, type, timestamp: getTimestamp() }]);
  };

  const handleUpdateDraft = (key: string, value: string) => {
    setDraft((prev: any) => ({ ...prev, [key]: value }));
  };

  const handleClearLogs = () => {
    setLogs([]);
    localStorage.removeItem('netaudit_logs');
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
      addLog('[ERROR] SIGINT received. Aborting process...', 'error');
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
    setCurrentAction("Initializing kernel...");
    abortRef.current.cancelled = false;
    lastLogRef.current = "";
    
    // 清空旧日志，给新扫描腾出空间
    if (logs.length > 0) {
        addLog(' ', 'raw'); // 空行
        addLog('--- NEW SESSION ---', 'raw');
    }

    const domains = draft.domainStr.split(',').map(d => d.trim()).filter(d => d);
    const metadata = {
        assetName: draft.assetName.trim() !== '' ? draft.assetName : `${config.defaultMetadata.assetNamePrefix}${draft.target}`,
        securityLevel: draft.securityLevel !== '' ? draft.securityLevel : config.defaultMetadata.securityLevel,
        location: draft.location.trim() !== '' ? draft.location : config.defaultMetadata.location,
        evaluator: draft.evaluator.trim() !== '' ? draft.evaluator : config.defaultMetadata.evaluator
    };
    
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
          setCurrentAction(log.replace(/^\[.*?\]\s*/, '')); // 进度条只显示去前缀后的动作
          
          if (log && log !== lastLogRef.current) {
             lastLogRef.current = log;
             // 智能添加日志，addLog 会自动解析 [PREFIX]
             addLog(log);
          }
        },
        abortRef.current,
        metadata
      );

      setProgress(100);
      setCurrentAction("Audit Task Completed.");
      // 延迟跳转，让用户看清最后的 Success 日志
      setTimeout(() => {
        onScanComplete(report);
        setIsScanning(false);
      }, 1500);
    } catch (err: any) {
      addLog(`[FATAL] ${err.message}`, 'error');
      setIsScanning(false);
      setProgress(0);
      setCurrentAction("Task Failed");
    }
  };

  // 终端日志颜色映射 (完全复刻截图)
  const renderLogPrefix = (type: string) => {
    const baseClass = "font-black mr-2";
    switch(type) {
        case 'info': return <span className={`${baseClass} text-[#00E5FF]`}>INFO</span>; // 亮蓝
        case 'warn': return <span className={`${baseClass} text-orange-400`}>WARN</span>; // 橙黄
        case 'error': 
        case 'fatal': return <span className={`${baseClass} text-red-500`}>ERROR</span>; // 红
        case 'success': return <span className={`${baseClass} text-[#CCFF00]`}>SUCCESS</span>; // 品牌绿
        default: return null;
    }
  };

  const getMessageStyle = (type: string) => {
      switch(type) {
        case 'error':
        case 'fatal': return 'text-red-400 font-bold'; // 错误信息本身也标红
        case 'warn': return 'text-orange-300';
        case 'success': return 'text-[#CCFF00]';
        default: return 'text-white/90'; // 默认信息为亮白
      }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-stretch animate-in slide-in-from-bottom-12 duration-1000">
      {/* 左侧配置面板 */}
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
                      <span className="text-[9px] font-black uppercase tracking-0.2em text-white/40 italic">测评对象画像</span>
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

      {/* 右侧日志面板 - Terminal 风格重构 */}
      <div className="lg:col-span-7 h-[750px]">
        <div className="tactical-card h-full flex flex-col overflow-hidden rounded-[2.5rem] border border-white/10 bg-[#0a0a0a] shadow-2xl relative group">
          
          {/* Terminal Header */}
          <div className="px-6 py-4 border-b border-white/5 bg-[#111] flex items-center justify-between shrink-0">
             <div className="flex items-center gap-3">
               <div className="flex gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
               </div>
               <span className="font-mono text-[10px] text-white/40 ml-2">root@netaudit-kernel:~</span>
             </div>
             <button onClick={handleClearLogs} className="flex items-center gap-2 px-3 py-1.5 rounded bg-white/5 hover:bg-white/10 text-[9px] font-mono text-white/30 transition-all">
               <Trash2 size={10} /> CLEAR
             </button>
          </div>

          {/* Log Area */}
          <div ref={scrollRef} className="p-6 font-mono text-[11px] flex-1 overflow-y-auto bg-[#050505] custom-scrollbar leading-relaxed">
            {logs.length === 0 && !isScanning && (
              <div className="h-full flex flex-col items-center justify-center space-y-4 opacity-20">
                <Terminal size={64} strokeWidth={1} />
                <span className="font-black uppercase tracking-widest text-xs">TERMINAL READY</span>
              </div>
            )}
            
            <div className="flex flex-col gap-0.5">
              {logs.map((log, i) => (
                <div key={i} className="flex gap-3 px-2 py-0.5 -mx-2 hover:bg-white/[0.02] rounded-sm group/log">
                  <span className="text-white/20 shrink-0 select-none opacity-50 w-8 text-right">]</span>
                  <div className="flex-1 break-all -ml-6">
                     <span className="text-white/20 mr-2 select-none">[{log.timestamp}]</span>
                     {renderLogPrefix(log.type)}
                     <span className={getMessageStyle(log.type)}>{log.msg}</span>
                  </div>
                </div>
              ))}
              
              {/* 底部光标行 */}
              {isScanning && (
                  <div className="flex gap-3 px-2 py-0.5 -mx-2 mt-1">
                      <span className="text-white/20 select-none opacity-50">[{getTimestamp()}]</span>
                      <div className="text-brand flex items-center">
                          <span className="mr-2 font-bold text-white/40">EXEC &gt;</span>
                          <span className="opacity-80">{currentAction}</span>
                          <span className="ml-1 w-2 h-4 bg-brand animate-pulse inline-block align-middle"></span>
                      </div>
                  </div>
              )}
            </div>
          </div>

          {/* 进度条 - 底部吸附 */}
          {isScanning && (
            <div className="h-1 bg-white/10 w-full shrink-0">
              <div 
                className="h-full bg-brand shadow-[0_0_10px_#CCFF00]" 
                style={{ width: `${progress}%`, transition: 'width 0.2s ease-out' }}
              ></div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanForm;
