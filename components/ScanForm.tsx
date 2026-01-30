
import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Loader2, Network, Globe, Radio, Box, Crosshair, Info, Trash2, ShieldAlert, Cpu } from 'lucide-react';
import { performScan } from '../services/scanService';
import { ScanReport, AppConfig, RiskLevel } from '../types';

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
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

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

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;
    
    setIsScanning(true);
    const domains = draft.domainStr.split(',').map(d => d.trim()).filter(d => d);
    const startTime = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    
    // 模拟启动序列
    addLog(`---------------- SESSION START [${startTime}] ----------------`, 'system');
    addLog(`KERNEL: 初始化安全审计内核 v3.1...`, 'info');
    addLog(`AUTH: 管理员 session 已激活。`, 'info');
    addLog(`TARGET_VECTOR: ${draft.target} [解析中...]`, 'info');
    
    try {
      addLog(`LOADER: 加载认证字典 (Users: ${config.dictionaries.usernames.split('\n').length}, Pass: ${config.dictionaries.passwords.split('\n').length})`, 'info');
      addLog(`ENGINE: 正在执行 TCP 同步扫描 (Range: ${draft.portRange})...`, 'info');
      
      const report = await performScan(
        config.apiBaseUrl, 
        draft.target, 
        draft.portRange, 
        config.ports, 
        config.dictionaries, 
        domains
      );

      // 详细回放扫描结果
      addLog(`NETWORK: 三次握手完成，发现 ${report.port_statuses.length} 个活动监听端口。`, 'success');
      
      for (const p of report.port_statuses) {
        addLog(`SCAN: 端口 ${p.port}/${p.protocol} 状态: ${p.status} -> ${p.detail}`, 'info');
        // 如果该端口有对应的漏洞
        const portDefects = report.defects.filter(d => d.id.includes(`-${p.port}`));
        for (const d of portDefects) {
           const logType = d.risk_level === RiskLevel.HIGH ? 'error' : d.risk_level === RiskLevel.MEDIUM ? 'warn' : 'info';
           addLog(`[VULN_DETECTED] [${d.risk_level}] ${d.check_item}: ${d.description}`, logType);
        }
      }

      if (report.summary.high > 0) {
        addLog(`CRITICAL: 检测到 ${report.summary.high} 个高危漏洞，建议立即加固。`, 'error');
      }

      addLog(`DONE: 审计档案已生成 [ID: ${report.id || 'TEMP'}], 评分: ${report.score}`, 'success');
      
      setTimeout(() => {
        onScanComplete(report);
        setIsScanning(false);
      }, 800);
    } catch (err: any) {
      addLog(`FATAL_ERROR: 引擎中断 -> ${err.message}`, 'error');
      setIsScanning(false);
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
        <div className="tactical-card p-1 bg-gradient-to-br from-white/10 to-transparent rounded-[2rem] h-full">
          <div className="bg-obsidian/95 rounded-[1.9rem] p-10 h-full flex flex-col justify-between overflow-y-auto custom-scrollbar">
            <div className="space-y-8">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 bg-brand text-black rounded-2xl flex items-center justify-center shadow-lg">
                  <Crosshair size={28} strokeWidth={2.5} />
                </div>
                <div>
                  <h2 className="text-3xl font-black italic uppercase leading-none tracking-tighter text-white">任务部署</h2>
                  <p className="text-[9px] font-black uppercase tracking-[0.3em] text-white/30 mt-2">资产深度审计配置</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="relative group">
                   <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 mb-2 px-1 block">资产 IP 地址</label>
                   <div className="relative">
                     <input 
                       value={draft.target} 
                       onChange={e => handleUpdateDraft('target', e.target.value)} 
                       disabled={isScanning} 
                       placeholder="例如: 127.0.0.1"
                       className="w-full pl-14 pr-6 py-5 bg-white/[0.03] border border-white/5 rounded-2xl text-md font-bold focus:border-brand/40 outline-none transition-all mono text-white/90" 
                     />
                     <Network className="absolute left-5 top-1/2 -translate-y-1/2 text-white/10" size={20} />
                   </div>
                </div>

                <div className="relative group">
                   <div className="flex justify-between items-center mb-2 px-1">
                      <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 block">待测域名集 (VHost)</label>
                      <div className="flex items-center gap-1 text-[8px] font-bold text-white/10 uppercase italic">
                         <Info size={10} /> 引擎将自动校验有效性
                      </div>
                   </div>
                   <div className="relative">
                     <textarea 
                       value={draft.domainStr} 
                       onChange={e => handleUpdateDraft('domainStr', e.target.value)} 
                       disabled={isScanning} 
                       rows={2} 
                       className="w-full pl-14 pr-6 py-4 bg-white/[0.03] border border-white/5 rounded-2xl text-xs font-bold focus:border-brand/40 outline-none transition-all mono text-white/90 resize-none" 
                       placeholder="例如: vuln.test, example.com" 
                     />
                     <Globe className="absolute left-5 top-6 text-white/10" size={20} />
                   </div>
                </div>

                <div className="relative group">
                   <label className="text-[10px] font-black uppercase tracking-[0.4em] text-white/20 mb-2 px-1 block">探测端口范围</label>
                   <div className="relative">
                     <input 
                       value={draft.portRange} 
                       onChange={e => handleUpdateDraft('portRange', e.target.value)} 
                       disabled={isScanning} 
                       placeholder="例如: 80, 443, 3306"
                       className="w-full pl-14 pr-6 py-5 bg-white/[0.03] border border-white/5 rounded-2xl text-md font-bold focus:border-brand/40 outline-none transition-all mono text-white/90" 
                     />
                     <Radio className="absolute left-5 top-1/2 -translate-y-1/2 text-white/10" size={20} />
                   </div>
                </div>
              </div>
            </div>

            <button onClick={handleScan} disabled={isScanning} className={`w-full py-7 mt-8 rounded-2xl text-xl font-black uppercase italic tracking-tighter flex items-center justify-center gap-4 transition-all ${isScanning ? 'bg-white/5 text-white/10 shadow-none' : 'bg-brand text-black hover:shadow-[0_0_50px_rgba(204,255,0,0.3)]'}`}>
              {isScanning ? <Loader2 className="animate-spin" /> : <Play fill="currentColor" size={20} />}
              <span>{isScanning ? '正在执行审计...' : '启动审计扫描引擎'}</span>
            </button>
          </div>
        </div>
      </div>

      <div className="lg:col-span-7 h-[650px]">
        <div className="tactical-card h-full flex flex-col overflow-hidden rounded-[2.5rem] border border-white/10 bg-obsidian/40 shadow-2xl">
          <div className="px-8 py-5 border-b border-white/5 bg-white/[0.02] flex items-center justify-between shrink-0">
             <div className="flex items-center gap-3">
               <Terminal size={14} className="text-brand" />
               <span className="font-black uppercase tracking-[0.5em] text-[10px] text-white/40 italic">审计终端内核日志</span>
             </div>
             <button 
               onClick={handleClearLogs}
               className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-danger/20 hover:text-danger text-[9px] font-black uppercase tracking-widest transition-all text-white/20"
             >
               <Trash2 size={12} /> 清除日志
             </button>
          </div>
          <div ref={scrollRef} className="p-8 font-mono text-[11px] flex-1 overflow-y-auto bg-black/60 custom-scrollbar scanline-container">
            {logs.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center space-y-6 opacity-10">
                <Box size={40} className="animate-pulse" />
                <span className="font-black uppercase tracking-[0.8em]">SYSTEM READY</span>
              </div>
            )}
            <div className="space-y-2">
              {logs.map((log, i) => (
                <div key={i} className={`flex gap-4 animate-in slide-in-from-left-2 duration-200 ${getLogColor(log.type)}`}>
                  {log.type !== 'system' && (
                    <span className="opacity-30 shrink-0 font-black text-[9px]">[{i.toString().padStart(3, '0')}]</span>
                  )}
                  <span className="leading-relaxed flex-1 break-all">{log.msg}</span>
                  {log.type === 'error' && <ShieldAlert size={12} className="shrink-0 mt-0.5" />}
                  {log.type === 'info' && i % 5 === 0 && <Cpu size={12} className="shrink-0 mt-0.5 opacity-20" />}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanForm;
