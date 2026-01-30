
import React, { useState } from 'react';
import { ScanReport, RiskLevel, Protocol, AppConfig } from '../types';
import { AlertTriangle, ChevronDown, ChevronRight, Server, Shield, Globe, Lock, Activity, Sparkles, Loader2, MessageSquareText, X, Key, Copy, Check, Skull, Target, Search, Database, Radar as RadarIcon } from 'lucide-react';
import { generateAIAdvice } from '../services/aiService';

interface ResultsViewProps {
  report: ScanReport | null;
  config: AppConfig;
}

const ResultsView: React.FC<ResultsViewProps> = ({ report, config }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [aiResult, setAiResult] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!report) return (
    <div className="space-y-10 animate-in fade-in duration-700">
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-5xl font-black uppercase italic tracking-tighter glow-text">资产分析中心</h2>
          <p className="font-bold text-white/20 mt-2 uppercase tracking-widest text-sm">当前状态：威胁建模待命</p>
        </div>
      </div>
      
      <div className="tactical-card min-h-[600px] rounded-[3rem] border border-white/5 relative overflow-hidden flex flex-col items-center justify-center p-12 scanline-container">
        {/* 高级战术背景 */}
        <div className="absolute inset-0 opacity-10 pointer-events-none">
           <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(204,255,0,0.15)_0%,transparent_75%)]"></div>
           <svg width="100%" height="100%" className="absolute inset-0">
             <defs>
               <pattern id="grid-empty" width="60" height="60" patternUnits="userSpaceOnUse">
                 <path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(204,255,0,0.3)" strokeWidth="0.5" />
                 <circle cx="0" cy="0" r="1.5" fill="rgba(204,255,0,0.5)" />
               </pattern>
             </defs>
             <rect width="100%" height="100%" fill="url(#grid-empty)" />
           </svg>
           
           {/* 雷达环 */}
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[900px] h-[900px] border border-brand/5 rounded-full"></div>
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] border border-brand/5 rounded-full"></div>
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[300px] h-[300px] border border-brand/10 rounded-full shadow-[0_0_100px_rgba(204,255,0,0.05)]"></div>
           
           {/* 雷达扫描指针 */}
           <div className="absolute top-1/2 left-1/2 w-[450px] h-[450px] origin-top-left -translate-y-full -translate-x-full overflow-hidden pointer-events-none">
              <div className="w-full h-full bg-gradient-to-br from-brand/20 to-transparent rounded-tl-full animate-radar origin-bottom-right"></div>
           </div>
        </div>
        
        <div className="relative z-10 flex flex-col items-center animate-float">
          <div className="w-48 h-48 bg-white/[0.02] rounded-[3.5rem] flex items-center justify-center mb-12 border border-white/10 shadow-2xl relative group">
             <div className="absolute inset-0 rounded-[3.5rem] bg-brand/5 blur-2xl group-hover:bg-brand/10 transition-all duration-1000"></div>
             <div className="absolute inset-0 rounded-[3.5rem] border-2 border-brand/10 animate-pulse"></div>
             <RadarIcon size={72} className="text-brand/40 group-hover:text-brand transition-all duration-500 transform group-hover:scale-110" />
          </div>
          
          <div className="text-center space-y-4">
            <h3 className="text-5xl font-black italic tracking-tighter uppercase text-white/90">待锁定目标向量</h3>
            <div className="h-1.5 w-24 bg-brand/50 mx-auto rounded-full shadow-[0_0_20px_rgba(204,255,0,0.5)]"></div>
            <p className="text-[10px] font-black text-white/20 uppercase tracking-[0.5em] max-w-sm mx-auto leading-relaxed mt-6">
              引擎处于无损监听状态<br/>
              请下发“审计任务”指令以同步资产快照
            </p>
          </div>
          
          <div className="mt-16 flex gap-6 items-center">
             <div className="flex items-center gap-3 px-5 py-2.5 bg-black/40 rounded-xl border border-white/5 opacity-50">
                <Activity size={14} className="text-brand" />
                <span className="text-[9px] font-black uppercase tracking-widest text-white/60">内核版本: 3.1-STABLE</span>
             </div>
             <div className="flex items-center gap-3 px-5 py-2.5 bg-black/40 rounded-xl border border-white/5 opacity-50">
                <Database size={14} className="text-info" />
                <span className="text-[9px] font-black uppercase tracking-widest text-white/60">持久化存储: 就绪</span>
             </div>
          </div>
        </div>
      </div>
    </div>
  );

  const handleAiAnalysis = async () => {
    setIsAiLoading(true);
    const advice = await generateAIAdvice(report, config.aiConfig);
    setAiResult(advice);
    setIsAiLoading(false);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getRiskStyle = (level: RiskLevel, isCompromised: boolean) => {
    if (isCompromised) return 'bg-danger text-white animate-pulse shadow-[0_0_30px_rgba(255,0,76,0.6)]';
    switch (level) {
      case RiskLevel.HIGH: return 'bg-danger text-white';
      case RiskLevel.MEDIUM: return 'bg-[#FF6B00] text-black';
      case RiskLevel.LOW: return 'bg-info text-black';
      default: return 'bg-white text-black';
    }
  };

  const getProtocolIcon = (proto: Protocol) => {
    switch (proto) {
      case Protocol.TLS: return <Lock size={14} />;
      case Protocol.SSH: return <Server size={14} />;
      case Protocol.HTTP: return <Globe size={14} />;
      case Protocol.DNS: return <Shield size={14} />;
      default: return <Server size={14} />;
    }
  };

  return (
    <div className="space-y-8 animate-in slide-in-from-bottom-6 duration-700">
      <div className="flex justify-between items-end border-b border-white/10 pb-6">
        <div>
          <h2 className="text-5xl font-black uppercase italic tracking-tighter glow-text">资产分析中心</h2>
          <p className="font-bold text-brand mt-2 uppercase tracking-widest text-sm">资产：{report.target} | 发现 {report.defects.length} 处漏洞点</p>
        </div>
        <div className="flex gap-4">
          <button 
            onClick={handleAiAnalysis}
            disabled={isAiLoading}
            className="bg-indigo-600 text-white px-6 py-3 rounded-xl font-black italic uppercase text-xs flex items-center gap-3 hover:shadow-[0_0_30px_rgba(79,70,229,0.3)] transition-all disabled:opacity-50"
          >
            {isAiLoading ? <Loader2 className="animate-spin" size={16} /> : <Sparkles size={16} />}
            AI 专家研判
          </button>
        </div>
      </div>

      {aiResult && (
        <div className="tactical-card p-10 rounded-[2.5rem] bg-indigo-500/5 border border-indigo-500/20 animate-in zoom-in-95 duration-500 relative group">
           <div className="flex justify-between items-start mb-6">
              <h3 className="text-xl font-black italic uppercase flex items-center gap-3 text-indigo-400">
                <MessageSquareText size={22} /> AI 审计顾问意见书
              </h3>
              <button onClick={() => setAiResult(null)} className="p-2 hover:bg-white/5 rounded-full transition-colors">
                <X size={16} className="text-white/20" />
              </button>
           </div>
           <div className="prose prose-invert prose-indigo max-w-none font-bold text-sm text-white/70 leading-relaxed italic whitespace-pre-wrap">
              {aiResult}
           </div>
        </div>
      )}

      <div className="space-y-6">
        {report.defects.map((defect: any) => {
          const isCompromised = defect.id.includes('SSH-PWD') || (defect.protocol === Protocol.SSH && defect.risk_level === RiskLevel.HIGH);
          
          return (
            <div key={defect.id} className={`tactical-card overflow-hidden rounded-3xl border transition-all ${isCompromised ? 'border-danger/50 bg-danger/5' : 'border-white/5'}`}>
              <div 
                className={`p-6 flex items-center justify-between cursor-pointer hover:bg-white/5 transition-all ${expandedId === defect.id ? 'bg-white/5 border-b border-white/10' : ''}`}
                onClick={() => setExpandedId(expandedId === defect.id ? null : defect.id)}
              >
                <div className="flex items-center gap-8">
                  <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 shadow-lg ${getRiskStyle(defect.risk_level, isCompromised)}`}>
                    {isCompromised ? <Skull size={30} /> : <AlertTriangle size={30} />}
                  </div>
                  <div>
                    <div className="flex items-center gap-4 mb-2">
                      <span className="bg-white/10 text-white/60 px-3 py-1 text-[10px] font-black flex items-center gap-2 uppercase rounded-md">
                        {getProtocolIcon(defect.protocol)}
                        {defect.protocol}
                      </span>
                      {defect.domain && (
                         <span className="bg-brand/10 text-brand px-3 py-1 text-[10px] font-black flex items-center gap-2 uppercase rounded-md border border-brand/20">
                           <Target size={12} />
                           {defect.domain}
                         </span>
                      )}
                      {isCompromised && (
                         <span className="bg-danger text-white px-2 py-0.5 text-[8px] font-black uppercase rounded animate-shake">CRITICAL SYSTEM BREACH</span>
                      )}
                      <h3 className={`font-black text-xl italic ${isCompromised ? 'text-danger' : ''}`}>{defect.check_item}</h3>
                    </div>
                    <p className="text-xs font-bold text-white/40 uppercase tracking-widest">{defect.description}</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-10">
                  <span className={`px-4 py-1.5 text-xs font-black rounded-lg uppercase shadow-sm ${getRiskStyle(defect.risk_level, isCompromised)}`}>
                    {isCompromised ? '凭据失陷' : defect.risk_level}
                  </span>
                  {expandedId === defect.id ? <ChevronDown className="text-white/20" size={28} /> : <ChevronRight className="text-white/20" size={28} />}
                </div>
              </div>

              {expandedId === defect.id && (
                <div className="p-10 grid grid-cols-1 md:grid-cols-2 gap-10 bg-black/20">
                  <div>
                    <div className="flex justify-between items-center mb-4">
                      <h4 className="font-black text-[10px] uppercase tracking-widest text-brand bg-brand/10 inline-block px-3 py-1 rounded-md">
                        审计取证数据 (Evidence)
                      </h4>
                    </div>
                    <div className={`p-6 rounded-2xl font-mono text-sm leading-relaxed border ${isCompromised ? 'bg-danger/20 border-danger/40 text-white' : 'bg-white/5 border-white/5 text-brand/80'}`}>
                      {defect.detail_value}
                    </div>
                    
                    <h4 className="font-black text-[10px] uppercase tracking-widest mt-10 mb-4 text-emerald-400 bg-emerald-400/10 inline-block px-3 py-1 rounded-md">战术加固方案</h4>
                    <div className="bg-white/5 border border-white/5 p-6 rounded-2xl font-bold text-sm text-white/70 leading-relaxed italic">
                      {defect.suggestion}
                    </div>
                  </div>
                  
                  <div className="bg-brand/5 border border-brand/10 p-8 rounded-3xl relative overflow-hidden">
                    <h4 className="font-black text-[10px] uppercase tracking-widest mb-6 border-b border-brand/20 pb-4">合规准则审计对照 (MLPS)</h4>
                    <div className="space-y-6">
                      <div>
                        <p className="text-[10px] font-black uppercase text-brand/40 mb-2">标准控制域标识</p>
                        <p className="font-black text-lg leading-tight text-white/90">{defect.mlps_clause}</p>
                      </div>
                      <div className="mt-4 p-4 bg-white/5 border border-white/10 rounded-xl">
                         <p className="text-[10px] font-black text-white/40 uppercase mb-1">审计来源标识</p>
                         <p className="text-[10px] text-white/60 italic">该项基于资产 {report.target} {defect.domain ? `及域名 ${defect.domain} ` : ''}的深度指纹匹配算法产出。</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ResultsView;
