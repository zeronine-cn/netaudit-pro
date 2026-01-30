
import React from 'react';
import { ScanReport, RiskLevel } from '../types';
import { AlertTriangle, ShieldCheck, Layers, ShieldAlert, Cpu, Network, Lock, Zap, Shield, Radar, Fingerprint, Activity, Database } from 'lucide-react';

interface ComplianceViewProps {
  report: ScanReport | null;
}

const ComplianceView: React.FC<ComplianceViewProps> = ({ report }) => {
  // 定义等保三级控制域
  const domains = [
    { id: 'NW', name: '安全通信网络', icon: Network, keywords: ['通信', '网络', '边界'] },
    { id: 'BD', name: '安全区域边界', icon: Lock, keywords: ['访问控制', '边界防护'] },
    { id: 'CE', name: '安全计算环境', icon: Cpu, keywords: ['身份鉴别', '入侵防范', '数据保密'] },
    { id: 'MC', name: '安全管理中心', icon: ShieldCheck, keywords: ['审计', '集中管控'] },
  ];

  const getFindingsByDomain = (keywords: string[]) => {
    if (!report) return [];
    return report.defects.filter(d => 
      keywords.some(k => d.mlps_clause.includes(k) || d.check_item.includes(k))
    );
  };

  if (!report) {
    return (
      <div className="space-y-10 animate-in fade-in duration-1000">
        <div className="flex justify-between items-start border-b border-white/5 pb-8">
          <div>
            <h2 className="text-6xl font-black italic tracking-tighter uppercase mb-2 glow-text">合规映射矩阵</h2>
            <div className="flex items-center gap-3">
               <Layers size={14} className="text-brand" />
               <p className="text-xs font-bold text-white/40 uppercase tracking-widest">基于 GB/T 22239-2019 等级保护标准</p>
            </div>
          </div>
          <div className="flex items-center gap-4 py-2 px-4 bg-white/5 rounded-xl border border-white/10 opacity-40">
            <Activity size={14} className="text-brand animate-pulse" />
            <span className="text-[10px] font-black uppercase tracking-widest">合规分析引擎挂起</span>
          </div>
        </div>

        <div className="w-full h-[650px] tactical-card rounded-[4rem] border border-white/5 flex flex-col items-center justify-center relative overflow-hidden group scanline-container">
          {/* 背景装饰：网格、雷达、光晕 */}
          <div className="absolute inset-0 opacity-10 pointer-events-none">
             <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(204,255,0,0.1)_0%,transparent_75%)]"></div>
             <svg width="100%" height="100%" className="absolute inset-0">
               <defs>
                 <pattern id="grid-compliance" width="60" height="60" patternUnits="userSpaceOnUse">
                   <path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(204,255,0,0.2)" strokeWidth="0.5" />
                   <circle cx="0" cy="0" r="1" fill="rgba(204,255,0,0.3)" />
                 </pattern>
               </defs>
               <rect width="100%" height="100%" fill="url(#grid-compliance)" />
             </svg>
             
             {/* 装饰性雷达环 */}
             <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] border border-white/5 rounded-full"></div>
             <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] border border-white/5 rounded-full"></div>
             <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[450px] h-[450px] border-t border-brand/20 rounded-full animate-radar"></div>
          </div>
          
          <div className="relative z-10 flex flex-col items-center animate-float">
            <div className="w-48 h-48 bg-white/[0.02] rounded-[3.5rem] flex items-center justify-center mb-10 border border-white/10 shadow-2xl relative group">
               <div className="absolute inset-0 rounded-[3.5rem] bg-brand/5 blur-3xl group-hover:bg-brand/10 transition-all duration-1000"></div>
               <div className="absolute inset-[-10px] rounded-[4rem] border border-brand/10 animate-pulse"></div>
               <ShieldCheck size={80} className="text-brand/20 group-hover:text-brand/60 transition-all duration-700 transform group-hover:scale-110" />
            </div>
            
            <div className="text-center space-y-6">
              <h3 className="text-4xl font-black italic tracking-tighter uppercase text-white/90">等待合规数据源</h3>
              <div className="flex items-center justify-center gap-4">
                 <div className="h-px w-12 bg-gradient-to-r from-transparent to-brand/40"></div>
                 <div className="flex gap-2">
                    <div className="w-2 h-2 rounded-full bg-brand/60 animate-bounce"></div>
                    <div className="w-2 h-2 rounded-full bg-brand/40 animate-bounce [animation-delay:0.2s]"></div>
                    <div className="w-2 h-2 rounded-full bg-brand/20 animate-bounce [animation-delay:0.4s]"></div>
                 </div>
                 <div className="h-px w-12 bg-gradient-to-l from-transparent to-brand/40"></div>
              </div>
              <p className="text-[10px] font-black text-white/20 uppercase tracking-[0.5em] max-w-md mx-auto leading-relaxed">
                当前审计快照为空。请在 [审计任务] 模块启动探测程序，系统将根据扫描产出的漏洞特征自动匹配等保 2.0 合规条款。
              </p>
            </div>
            
            <div className="mt-16 grid grid-cols-4 gap-4">
               {domains.map(d => (
                  <div key={d.id} className="flex flex-col items-center gap-2 opacity-30 group-hover:opacity-100 transition-opacity">
                     <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center border border-white/10">
                        <d.icon size={16} />
                     </div>
                     <span className="text-[8px] font-black uppercase tracking-tighter">{d.id}</span>
                  </div>
               ))}
            </div>
          </div>
          
          {/* 四角装饰 */}
          <div className="absolute top-10 left-10 w-8 h-8 border-t-2 border-l-2 border-brand/20 rounded-tl-lg"></div>
          <div className="absolute top-10 right-10 w-8 h-8 border-t-2 border-r-2 border-brand/20 rounded-tr-lg"></div>
          <div className="absolute bottom-10 left-10 w-8 h-8 border-b-2 border-l-2 border-brand/20 rounded-bl-lg"></div>
          <div className="absolute bottom-10 right-10 w-8 h-8 border-b-2 border-r-2 border-brand/20 rounded-br-lg"></div>
        </div>
      </div>
    );
  }

  const totalRisks = report.defects.length;

  return (
    <div className="space-y-10 animate-in slide-in-from-bottom-6 duration-700">
      <div className="flex justify-between items-end border-b border-white/10 pb-6">
        <div>
          <h2 className="text-6xl font-black italic tracking-tighter uppercase mb-2 glow-text">合规映射矩阵</h2>
          <div className="flex items-center gap-3">
             <ShieldCheck size={18} className="text-brand" />
             <p className="text-sm font-bold text-white/40 uppercase tracking-widest">合规分析引擎 v3.1 | 标准集: 等保 2.0 L3</p>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
           <div className="px-4 py-2 bg-brand/10 border border-brand/20 rounded-lg text-[10px] font-black text-brand italic uppercase">
             风险对齐率: {totalRisks > 0 ? '未达标' : '全项通过'}
           </div>
           <span className="text-[10px] text-white/20 font-bold uppercase">最后分析时间: {report.timestamp}</span>
        </div>
      </div>

      {/* 控制域概览卡片组 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {domains.map((domain) => {
          const findings = getFindingsByDomain(domain.keywords);
          const hasHighRisk = findings.some(f => f.risk_level === RiskLevel.HIGH);
          
          return (
            <div key={domain.id} className={`tactical-card p-6 rounded-3xl border-l-4 transition-all hover:scale-[1.02] ${findings.length > 0 ? (hasHighRisk ? 'border-l-danger bg-danger/5' : 'border-l-orange-500 bg-orange-500/5') : 'border-l-brand bg-brand/5'}`}>
              <div className="flex justify-between items-start mb-6">
                <div className={`p-3 rounded-xl ${findings.length > 0 ? (hasHighRisk ? 'bg-danger text-white' : 'bg-orange-500 text-black') : 'bg-brand text-black'}`}>
                  <domain.icon size={20} />
                </div>
                <div className="text-right">
                  <div className="text-[10px] font-black text-white/20 uppercase tracking-tighter">异常项</div>
                  <div className="text-2xl font-black">{findings.length}</div>
                </div>
              </div>
              <h4 className="text-sm font-black uppercase mb-1">{domain.name}</h4>
              <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden mt-4">
                 <div 
                   className={`h-full transition-all duration-1000 ${findings.length === 0 ? 'w-full bg-brand' : 'w-1/3 bg-danger animate-pulse'}`}
                 ></div>
              </div>
            </div>
          );
        })}
      </div>

      {/* 详细合规映射列表 */}
      <div className="space-y-6">
        <div className="flex items-center gap-4 px-2">
           <Zap size={16} className="text-brand" />
           <h3 className="text-lg font-black uppercase italic tracking-widest">合规条款核查清单 (GB/T 22239)</h3>
        </div>

        <div className="grid grid-cols-1 gap-4">
          {report.defects.map((defect, idx) => (
            <div key={idx} className="tactical-card group overflow-hidden rounded-2xl border border-white/5 hover:border-white/10 transition-all flex flex-col md:flex-row">
               <div className={`md:w-48 p-6 flex flex-col items-center justify-center shrink-0 border-b md:border-b-0 md:border-r border-white/5 ${defect.risk_level === RiskLevel.HIGH ? 'bg-danger/10' : 'bg-white/5'}`}>
                  <div className="text-[10px] font-black text-white/30 uppercase tracking-widest mb-2">等保条款 ID</div>
                  <div className="text-xs font-black text-center text-white/80 leading-tight">{defect.mlps_clause.split('-').pop()}</div>
                  <div className={`mt-4 px-3 py-1 rounded text-[9px] font-black uppercase ${defect.risk_level === RiskLevel.HIGH ? 'bg-danger text-white' : 'bg-orange-500 text-black'}`}>
                    {defect.risk_level}
                  </div>
               </div>
               
               <div className="flex-1 p-6 space-y-4">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                     <div>
                        <div className="text-[9px] font-black text-brand uppercase tracking-[0.3em] mb-1">合规域: {defect.mlps_clause.split('-')[1]}</div>
                        <h4 className="text-xl font-black italic text-white/90">{defect.description}</h4>
                     </div>
                     <div className="px-4 py-2 bg-white/5 rounded-lg border border-white/5">
                        <span className="text-[10px] font-black text-white/20 uppercase block mb-1">技术验证项</span>
                        <span className="text-xs font-mono text-white/60">{defect.check_item}</span>
                     </div>
                  </div>
                  
                  <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                     <div className="flex items-center gap-2 mb-2">
                        <ShieldAlert size={12} className="text-danger" />
                        <span className="text-[10px] font-black uppercase text-white/40">不合规详情描述 (Gap Analysis)</span>
                     </div>
                     <p className="text-xs text-white/50 leading-relaxed italic">
                        该资产由于存在 {defect.detail_value}，未能满足等保关于“{defect.mlps_clause}”的要求。建议执行：{defect.suggestion}
                     </p>
                  </div>
               </div>
            </div>
          ))}

          {report.defects.length === 0 && (
            <div className="tactical-card p-20 flex flex-col items-center justify-center rounded-[3rem]">
               <ShieldCheck size={64} className="text-brand/20 mb-6" />
               <h3 className="text-2xl font-black italic uppercase text-brand">符合合规基线</h3>
               <p className="text-xs text-white/20 font-bold uppercase tracking-widest mt-2">未发现违反等保三级技术条款的风险项</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ComplianceView;
