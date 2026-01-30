
import React, { useEffect, useState } from 'react';
import { Clock, Fingerprint, Activity, ShieldCheck, Zap, TrendingUp } from 'lucide-react';
import { ScanReport } from '../types';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, ResponsiveContainer } from 'recharts';

interface DashboardProps {
  report: ScanReport | null;
  scanHistory: ScanReport[];
  onSelectReport: (report: ScanReport) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ report }) => {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  if (!report) {
    return (
      <div className="relative flex flex-col items-center justify-center min-h-[75vh] animate-in fade-in duration-1000">
        <Fingerprint size={100} strokeWidth={1} className="text-brand/60 animate-pulse mb-8" />
        <h3 className="text-5xl font-black italic tracking-tighter glow-text mb-4 uppercase">审计引擎待命</h3>
        <p className="text-white/20 font-bold uppercase tracking-[0.8em] text-[10px]">等待安全链路初始化</p>
      </div>
    );
  }

  // 模拟雷达图数据
  const radarData = [
    { subject: '身份鉴别', A: 100 - (report.summary.high * 15), fullMark: 100 },
    { subject: '访问控制', A: 100 - (report.summary.medium * 10), fullMark: 100 },
    { subject: '入侵防范', A: 85, fullMark: 100 },
    { subject: '数据保密', A: report.score, fullMark: 100 },
    { subject: '合规审计', A: 90, fullMark: 100 },
  ];

  return (
    <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-700">
      <div className="flex justify-between items-end pb-4 border-b border-white/5">
        <div>
           <div className="flex items-center gap-2 mb-1">
             <div className="w-2 h-2 rounded-full bg-brand animate-pulse"></div>
             <span className="text-[10px] font-black text-brand tracking-[0.2em] uppercase">核心节点已连接</span>
           </div>
           <h2 className="text-4xl font-black tracking-tighter italic uppercase">审计主控中心</h2>
        </div>
        <div className="flex gap-8 items-center font-mono text-right">
           <div>
             <div className="text-[10px] text-white/20 font-bold uppercase mb-1 flex items-center justify-end gap-2">
               <Clock size={12} /> 系统时间
             </div>
             <div className="text-2xl font-bold tracking-tighter text-white">{time.toLocaleTimeString('zh-CN', { hour12: false })}</div>
           </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
         {/* 安全评分看板 */}
         <div className="tactical-card md:col-span-5 p-10 rounded-[2.5rem] flex flex-col justify-between overflow-hidden relative group">
            <div className="absolute right-0 top-0 p-8 opacity-10 group-hover:opacity-20 transition-opacity">
               <TrendingUp size={120} />
            </div>
            <div>
              <span className="text-9xl font-black glow-text tracking-tighter leading-none">{report.score}</span>
              <p className="text-white/20 font-bold uppercase tracking-widest mt-4">Security Score Index</p>
            </div>
            <div className="mt-8 flex gap-4">
               <div className="px-3 py-1 bg-brand/10 border border-brand/20 rounded text-[10px] font-black text-brand uppercase">风险等级: {report.score > 80 ? '低' : '中'}</div>
               <div className="px-3 py-1 bg-white/5 border border-white/10 rounded text-[10px] font-black text-white/40 uppercase">资产: {report.target}</div>
            </div>
         </div>

         {/* 风险雷达图 */}
         <div className="tactical-card md:col-span-4 p-6 rounded-[2.5rem] flex flex-col items-center">
            <h4 className="text-[10px] font-black uppercase text-white/30 tracking-widest mb-4">合规能力维度分析</h4>
            <div className="w-full h-48">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                  <PolarGrid stroke="#ffffff11" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#ffffff44', fontSize: 10, fontWeight: 800 }} />
                  <Radar name="Score" dataKey="A" stroke="#CCFF00" fill="#CCFF00" fillOpacity={0.3} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
         </div>

         {/* 简要统计 */}
         <div className="tactical-card md:col-span-3 p-8 rounded-[2.5rem] flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex justify-between items-center pb-3 border-b border-white/5">
                <span className="text-[10px] font-black uppercase text-danger">高危漏洞</span>
                <span className="text-2xl font-black">{report.summary.high}</span>
              </div>
              <div className="flex justify-between items-center pb-3 border-b border-white/5">
                <span className="text-[10px] font-black uppercase text-orange-500">中危漏洞</span>
                <span className="text-2xl font-black">{report.summary.medium}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-black uppercase text-info">低危漏洞</span>
                <span className="text-2xl font-black">{report.summary.low}</span>
              </div>
            </div>
            <div className="mt-8 bg-brand/10 p-4 rounded-xl border border-brand/20">
               <p className="text-[9px] font-bold text-brand uppercase leading-tight italic">
                 建议: 优先修复端口 {report.port_statuses.find(p => p.protocol === 'HTTP')?.port || '80'} 的版本泄露问题。
               </p>
            </div>
         </div>
      </div>
    </div>
  );
};

export default Dashboard;
