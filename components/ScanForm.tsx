
import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Loader2, Network, Globe, Radio, Box, Crosshair, Info, Trash2, ShieldAlert, Cpu, Zap, Activity, StopCircle, History, ChevronRight } from 'lucide-react';
import { performScan } from '../services/scanService';
import { ScanReport, AppConfig, RiskLevel, ScanMode } from '../types';

interface ScanFormProps {
  onScanComplete: (report: ScanReport) => void;
  config: AppConfig;
  draft: { target: string; domainStr: string; portRange: string };
  setDraft: React.Dispatch<React.SetStateAction<{ target: string; domainStr: string; portRange: string }>>;
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

  const handleUpdateDraft = (key: keyof typeof draft, value: string) => {
    setDraft(prev => ({ ...prev, [key]: value }));
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

  // 鼠标移入逻辑：清除隐藏定时器并立即显示
  const handleMouseEnter = () => {
    if (hideTimeoutRef.current) window.clearTimeout(hideTimeoutRef.current);
    setShowHistoryPopup(true);
  };

  // 鼠标移出逻辑：增加一小段延迟，给用户时间移动到菜单上
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
    const startTime = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    
    addLog(`---------------- SESSION START [${startTime}] ----------------`, 'system');
    addLog(`KERNEL: 初始化审计内核 v3.1...`, 'info');
    addLog(`MODE: ${scanMode} | BRUTE_FORCE: ${enableBrute ? '开启' : '关闭'}`, 'info');
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
        abortRef.current
      );

      setProgress(100);
      setCurrentAction("审计完成");
      
      addLog(`NETWORK: 审计作业结束，共发现 ${report.port_statuses.length} 个活动向量。`, 'success');
      
      for (const p of report.port_statuses) {
        addLog(`SCAN: 端口 ${p.port}/${p.protocol} 识别成功: ${p.detail}`, 'info');
        const portDefects = report.defects.filter(d => d.id.includes(`-${p.port}`));
        for (const d of portDefects) {
           const logType = d.risk_level === RiskLevel.HIGH ? 'error' : d.risk_level === RiskLevel.MEDIUM ? 'warn' : 'info';
           addLog(`[DEFECT] [${d.risk_level}] ${d.check_item}`, logType);
        }
      }

      addLog(`DONE: 审计档案已安全持久化，评分: ${report.score}`, 'success');
      
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
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start animate-in slide-in-from-bottom-12 duration-1000">
      <div className="lg:col-span-5 h-[650px]">
        <div className="tactical-card p-1 bg-gradient-to-br from-white/10 to-transparent rounded-[2rem] h-full shadow-2xl">
          <div className="bg-obsidian/95 rounded-[1.9rem] p-10 h-full flex flex-col justify-between overflow-y-auto custom-scrollbar">
            <div className="space-y-6">
              <div className="flex items-center gap-5 mb-2">
                <div className="w-14 h-14 bg-brand text-black rounded-2xl flex items-center justify-center shadow-lg transform rotate-3">
                  <Crosshair size={28} strokeWidth={2.5} />
                </div>
                <div>
                  <h2 className="text-3xl font-black italic uppercase leading-none tracking-tighter text-white">审计部署</h2>
                  <p className="text-[9px] font-black uppercase tracking-[0.3em] text-white/30 mt-2">安全合规审计策略配置</p>
                </div>
              </div>

              <div className="space-y-4">
                {/* 目标 IP */}
                <div 
                  className="relative group"
                  onMouseEnter={handleMouseEnter}
                  onMouseLeave={handleMouseLeave}
                >
                   <div className="flex justify-between items-center mb-1.5 px-1">
                     <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 block">目标 IP 地址</label>
                     {targetHistory.length > 0 && (
                        <div className="opacity-10 group-hover:opacity-100 transition-opacity">
                           <History size={10} className="text-brand" />
                        </div>
                     )}
                   </div>
                   <div className="relative">
                     <input 
                       value={draft.target} 
                       onChange={e => handleUpdateDraft('target', e.target.value)} 
                       disabled={isScanning} 
                       className="w-full pl-12 pr-6 py-4 bg-white/[0.03] border border-white/5 rounded-xl text-md font-bold focus:border-brand/40 outline-none transition-all mono text-white/90" 
                       placeholder="127.0.0.1"
                     />
                     <Network className="absolute left-4 top-1/2 -translate-y-1/2 text-white/10" size={18} />
                   </div>

                   {/* 悬停历史弹出菜单：消除 top 间距，改为内部 padding 确保鼠标路径连贯 */}
                   {showHistoryPopup && targetHistory.length > 0 && !isScanning && (
                     <div className="absolute top-full left-0 w-full z-[100] pt-2 animate-in fade-in slide-in-from-top-1 duration-200">
                        <div className="bg-black/90 backdrop-blur-xl border border-brand/20 rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.8),0_0_20px_rgba(204,255,0,0.1)] p-3">
                           <div className="px-3 mb-2 flex items-center gap-2 border-b border-white/5 pb-2">
                              <Zap size={10} className="text-brand" />
                              <span className="text-[8px] font-black text-white/30 uppercase tracking-[0.2em]">最近审计足迹</span>
                           </div>
                           <div className="space-y-1">
                              {targetHistory.map((ip, idx) => (
                                <button
                                  key={idx}
                                  onClick={() => {
                                    handleUpdateDraft('target', ip);
                                    setShowHistoryPopup(false);
                                  }}
                                  className="w-full flex items-center justify-between px-4 py-3 rounded-lg hover:bg-brand hover:text-black transition-all group/item"
                                >
                                  <span className="text-xs font-mono font-bold tracking-wider">{ip}</span>
                                  <ChevronRight size={12} className="opacity-20 group-hover/item:opacity-100" />
                                </button>
                              ))}
                           </div>
                        </div>
                     </div>
                   )}
                </div>

                {/* 域名 VHost 输入框 */}
                <div className="relative group">
                   <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 mb-1.5 px-1 block">关联域名 (VHost)</label>
                   <div className="relative">
                     <textarea 
                       value={draft.domainStr} 
                       onChange={e => handleUpdateDraft('domainStr', e.target.value)} 
                       disabled={isScanning} 
                       rows={2}
                       className="w-full pl-12 pr-6 py-4 bg-white/[0.03] border border-white/5 rounded-xl text-xs font-bold focus:border-brand/40 outline-none transition-all mono text-white/90 resize-none" 
                       placeholder="example.com, vuln.test"
                     />
                     <Globe className="absolute left-4 top-5 text-white/10" size={18} />
                   </div>
                </div>

                {/* 模式选择 */}
                <div className="space-y-1.5">
                   <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 px-1 block">审计引擎深度</label>
                   <div className="grid grid-cols-2 gap-3">
                      {[ScanMode.QUICK, ScanMode.DEEP].map(mode => (
                        <button
                          key={mode}
                          onClick={() => setScanMode(mode)}
                          disabled={isScanning}
                          className={`py-3 rounded-xl text-[10px] font-black uppercase italic tracking-widest border transition-all ${scanMode === mode ? 'bg-brand text-black border-brand shadow-[0_0_15px_rgba(204,255,0,0.2)]' : 'bg-white/5 text-white/30 border-white/10 hover:bg-white/10'}`}
                        >
                          {mode}
                        </button>
                      ))}
                   </div>
                </div>

                {/* 弱口令勾选 */}
                <div className={`p-4 rounded-xl border transition-all ${enableBrute ? 'bg-brand/5 border-brand/20' : 'bg-white/5 border-white/10'} ${scanMode === ScanMode.QUICK ? 'opacity-20 grayscale cursor-not-allowed' : ''}`}>
                   <label className="flex items-center gap-4 cursor-pointer">
                      <input 
                        type="checkbox" 
                        checked={enableBrute} 
                        onChange={e => setEnableBrute(e.target.checked)}
                        disabled={isScanning || scanMode === ScanMode.QUICK}
                        className="w-4 h-4 rounded border-white/10 bg-black/40 text-brand focus:ring-brand"
                      />
                      <div className="flex-1">
                        <div className="text-[10px] font-black text-white/80 uppercase">执行弱口令审计</div>
                        <div className="text-[8px] font-bold text-white/20 uppercase tracking-tighter italic">针对 SSH 等服务的字典扫描</div>
                      </div>
                      {enableBrute && <ShieldAlert size={14} className="text-brand animate-pulse" />}
                   </label>
                </div>

                {/* 探测端口 */}
                <div className="relative group">
                   <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 mb-1.5 px-1 block">探测端口集</label>
                   <div className="relative">
                     <input 
                       value={draft.portRange} 
                       onChange={e => handleUpdateDraft('portRange', e.target.value)} 
                       disabled={isScanning} 
                       className="w-full pl-12 pr-6 py-4 bg-white/[0.03] border border-white/5 rounded-xl text-md font-bold focus:border-brand/40 outline-none transition-all mono text-white/90" 
                       placeholder="22, 80, 443"
                     />
                     <Radio className="absolute left-4 top-1/2 -translate-y-1/2 text-white/10" size={18} />
                   </div>
                </div>
              </div>
            </div>

            {isScanning ? (
              <button onClick={handleStopScan} className="w-full py-6 mt-6 rounded-2xl text-lg font-black uppercase italic tracking-tighter flex items-center justify-center gap-4 bg-danger/20 text-danger border border-danger/40 hover:bg-danger hover:text-white transition-all">
                <StopCircle size={22} />
                <span>中止审计作业</span>
              </button>
            ) : (
              <button onClick={handleScan} className="w-full py-6 mt-6 rounded-2xl text-lg font-black uppercase italic tracking-tighter flex items-center justify-center gap-4 bg-brand text-black hover:shadow-[0_0_50px_rgba(204,255,0,0.4)] transition-all">
                <Play fill="currentColor" size={18} />
                <span>下发审计指令</span>
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="lg:col-span-7 h-[650px]">
        <div className="tactical-card h-full flex flex-col overflow-hidden rounded-[2.5rem] border border-white/10 bg-obsidian/40 shadow-2xl relative">
          <div className="px-8 py-5 border-b border-white/5 bg-white/[0.02] flex items-center justify-between shrink-0">
             <div className="flex items-center gap-3">
               <Terminal size={14} className="text-brand" />
               <span className="font-black uppercase tracking-[0.5em] text-[10px] text-white/40 italic">审计终端实时日志</span>
             </div>
             <button 
               onClick={handleClearLogs}
               className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-danger/20 hover:text-danger text-[9px] font-black uppercase tracking-widest transition-all text-white/20"
             >
               <Trash2 size={12} /> 清除
             </button>
          </div>

          <div ref={scrollRef} className="p-8 font-mono text-[11px] flex-1 overflow-y-auto bg-black/60 custom-scrollbar scanline-container">
            {logs.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center space-y-6 opacity-10">
                <Box size={40} className="animate-pulse" />
                <span className="font-black uppercase tracking-[0.8em]">KERNEL READY</span>
              </div>
            )}
            <div className="space-y-2 pb-24">
              {logs.map((log, i) => (
                <div key={i} className={`flex gap-4 animate-in slide-in-from-left-2 duration-200 ${getLogColor(log.type)}`}>
                  {log.type !== 'system' && (
                    <span className="opacity-20 shrink-0 font-black text-[9px]">[{i.toString().padStart(3, '0')}]</span>
                  )}
                  <span className="leading-relaxed flex-1 break-all">{log.msg}</span>
                </div>
              ))}
              
              {isScanning && (
                <div className="mt-8 p-6 bg-brand/5 border border-brand/20 rounded-2xl animate-in slide-in-from-bottom-4 duration-500 shadow-[0_0_30px_rgba(204,255,0,0.05)] relative overflow-hidden">
                  <div className="absolute top-0 left-0 w-1.5 h-full bg-brand"></div>
                  <div className="flex justify-between items-center mb-3">
                    <div className="flex items-center gap-3">
                       <Zap size={14} className="text-brand animate-pulse" />
                       <span className="text-[10px] font-black text-brand uppercase tracking-widest italic">引擎作业中...</span>
                    </div>
                    <span className="text-[10px] font-mono text-brand/60 font-black tracking-widest">{progress}%</span>
                  </div>
                  <div className="text-white font-black text-xs mb-3 uppercase italic truncate tracking-tight">{currentAction}</div>
                  <div className="h-2 bg-white/5 rounded-full overflow-hidden flex items-center">
                    <div 
                      className="h-full bg-brand shadow-[0_0_15px_#CCFF00] transition-all duration-300" 
                      style={{ width: `${progress}%` }}
                    ></div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="px-8 py-3 bg-white/[0.02] border-t border-white/5 flex justify-between items-center shrink-0">
             <div className="flex items-center gap-4 text-[9px] font-bold text-white/20 uppercase tracking-widest">
                <span className="flex items-center gap-1.5"><Cpu size={10} /> CORE: v3.1</span>
                <span className="flex items-center gap-1.5"><Activity size={10} /> THREADS: 50</span>
             </div>
             {isScanning && (
                <div className="flex items-center gap-3">
                   <div className="w-1.5 h-1.5 rounded-full bg-brand animate-ping"></div>
                   <span className="text-[9px] font-black text-brand italic">TASK_RUNNING</span>
                </div>
             )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanForm;
