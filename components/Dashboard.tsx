
import React, { useEffect, useState, useMemo } from 'react';
import { Clock, Fingerprint, Activity, ShieldCheck, Zap, TrendingUp, History } from 'lucide-react';
import { ScanReport } from '../types';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ReferenceLine } from 'recharts';

interface DashboardProps {
  report: ScanReport | null;
  scanHistory: ScanReport[];
  onSelectReport: (report: ScanReport) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ report, scanHistory }) => {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // 计算趋势数据
  const trendData = useMemo(() => {
    if (!report) return [];
    
    // 1. 筛选当前目标的历史记录
    // 2. 确保包含当前报告（防止还没同步到 history 时显示缺失）
    const relatedReports = scanHistory.filter(r => r.target === report.target);
    const combined = [...relatedReports];
    
    // 如果当前报告不在历史记录中（通过时间戳简单去重），则添加进去以便显示最新点
    if (!combined.find(r => r.timestamp === report.timestamp)) {
        combined.push(report);
    }

    // 3. 按时间正序排列并格式化
    return combined
      .sort((a, b) => new Date(a.timestamp.replace(' ', 'T')).getTime() - new Date(b.timestamp.replace(' ', 'T')).getTime())
      .map(r => {
        // 格式化时间轴标签：只显示 月-日 时:分
        const dateObj = new Date(r.timestamp.replace(' ', 'T'));
        const shortTime = `${dateObj.getMonth() + 1}/${dateObj.getDate()} ${String(dateObj.getHours()).padStart(2, '0')}:${String(dateObj.getMinutes()).padStart(2, '0')}`;
        return {
          originalTime: r.timestamp,
          time: shortTime,
          score: r.score,
          highRisks: r.summary.high
        };
      });
  }, [report, scanHistory]);

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

         {/* 新增：安全评分趋势遥测图 */}
         <div className="tactical-card md:col-span-12 p-8 rounded-[2.5rem] relative overflow-hidden min-h-[350px] flex flex-col border border-white/10">
            {/* 头部信息 */}
            <div className="flex justify-between items-start mb-6 z-10">
               <div>
                  <h3 className="text-xl font-black italic uppercase flex items-center gap-3">
                     <History size={24} className="text-brand" /> 
                     资产安全评分走势 (SECURITY TREND)
                  </h3>
                  <p className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em] mt-1 flex items-center gap-2">
                     <span className="w-1.5 h-1.5 rounded-full bg-brand/50"></span>
                     TARGET NODE: {report.target}
                     <span className="w-px h-3 bg-white/10"></span>
                     DATAPOINTS: {trendData.length}
                  </p>
               </div>
               
               {/* 简易图例 */}
               <div className="flex items-center gap-4 text-[9px] font-black uppercase text-white/30">
                  <div className="flex items-center gap-1.5"><div className="w-3 h-1 bg-[#CCFF00]"></div> 评分曲线</div>
                  <div className="flex items-center gap-1.5"><div className="w-3 h-1 border-t border-dashed border-[#ff004c]"></div> 60分警戒线</div>
               </div>
            </div>

            {/* 核心图表区 */}
            <div className="flex-1 w-full h-[240px] relative z-10">
               <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                     <defs>
                        <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                           <stop offset="5%" stopColor="#CCFF00" stopOpacity={0.3}/>
                           <stop offset="95%" stopColor="#CCFF00" stopOpacity={0}/>
                        </linearGradient>
                     </defs>
                     <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                     <XAxis 
                        dataKey="time" 
                        stroke="#ffffff40" 
                        tick={{fontSize: 10, fontFamily: 'monospace'}} 
                        tickLine={false}
                        axisLine={false}
                        interval="preserveStartEnd"
                     />
                     <YAxis 
                        stroke="#ffffff40" 
                        tick={{fontSize: 10, fontFamily: 'monospace'}} 
                        tickLine={false}
                        axisLine={false}
                        domain={[0, 100]}
                     />
                     <Tooltip 
                        contentStyle={{ backgroundColor: '#050505ee', border: '1px solid #333', borderRadius: '12px', boxShadow: '0 0 20px rgba(0,0,0,0.8)' }}
                        itemStyle={{ color: '#CCFF00', fontSize: '12px', fontWeight: 'bold', fontFamily: 'monospace' }}
                        labelStyle={{ color: '#888', fontSize: '10px', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}
                        cursor={{ stroke: '#CCFF00', strokeWidth: 1, strokeDasharray: '4 4' }}
                        formatter={(value: number) => [`${value} 分`, '安全评分']}
                     />
                     <ReferenceLine y={60} stroke="#ff004c" strokeDasharray="3 3" label={{ position: 'insideTopRight', value: 'PASS LINE (60)', fill: '#ff004c', fontSize: 9, fontWeight: 900 }} />
                     <Area 
                        type="monotone" 
                        dataKey="score" 
                        stroke="#CCFF00" 
                        strokeWidth={3}
                        fillOpacity={1} 
                        fill="url(#colorScore)" 
                        animationDuration={1500}
                        activeDot={{ r: 6, strokeWidth: 0, fill: '#fff' }}
                     />
                  </AreaChart>
               </ResponsiveContainer>
            </div>
            
            {/* 背景装饰网格 */}
            <div className="absolute inset-0 opacity-5 pointer-events-none">
               <div className="w-full h-full bg-[linear-gradient(to_right,rgba(255,255,255,0.1)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.1)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
            </div>
         </div>
      </div>
    </div>
  );
};

export default Dashboard;
