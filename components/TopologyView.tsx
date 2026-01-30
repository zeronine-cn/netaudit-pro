import React from 'react';
import { ScanReport } from '../types';
import { Server, Radar, Target, WifiOff } from 'lucide-react';

interface TopologyViewProps { report: ScanReport | null; }

const TopologyView: React.FC<TopologyViewProps> = ({ report }) => {
  if (!report) {
    return (
      <div className="relative w-full h-[650px] tactical-card rounded-[3rem] overflow-hidden flex flex-col items-center justify-center animate-in fade-in duration-1000">
        {/* 背景格栅与雷达装饰 */}
        <div className="absolute inset-0 opacity-10">
          <div className="w-full h-full bg-[radial-gradient(circle_at_center,rgba(204,255,0,0.1)_0%,transparent_70%)]"></div>
          <svg width="100%" height="100%">
            <defs>
              <pattern id="grid-topology" width="50" height="50" patternUnits="userSpaceOnUse">
                <path d="M 50 0 L 0 0 0 50" fill="none" stroke="white" strokeWidth="0.5"/>
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid-topology)" />
          </svg>
        </div>

        {/* 中央雷达盘 */}
        <div className="relative z-10 w-80 h-80 flex items-center justify-center">
          <div className="absolute inset-0 border border-white/5 rounded-full"></div>
          <div className="absolute inset-8 border border-white/5 rounded-full"></div>
          <div className="absolute inset-20 border border-white/5 rounded-full"></div>
          
          {/* 雷达扫描线 */}
          <div className="absolute inset-0 border-t border-brand/40 rounded-full animate-[spin_4s_linear_infinite] origin-center shadow-[0_-10px_30px_rgba(204,255,0,0.1)]"></div>
          
          <div className="flex flex-col items-center">
            <Radar size={48} className="text-white/10 mb-4 animate-pulse" />
            <div className="text-[10px] font-black text-white/20 uppercase tracking-[0.5em] text-center px-4">
              未检测到活动的资产节点<br/>
              <span className="text-brand/40 italic">被动感应监听中...</span>
            </div>
          </div>
        </div>

        {/* 底部文字信息 */}
        <div className="mt-12 text-center relative z-10">
          <h3 className="text-3xl font-black italic tracking-tighter uppercase mb-2">等待锁定目标向量</h3>
          <p className="text-[10px] font-bold text-white/20 uppercase tracking-widest max-w-md mx-auto leading-relaxed">
             拓扑绘制引擎已准备就绪。请启动“审计任务”对目标子网进行深度指纹探测，以实时构建资产连接依赖树。
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-1000">
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-4xl font-black italic tracking-tighter uppercase glow-text">资产连接拓扑图</h2>
          <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.4em] mt-1">网络节点连接拓扑</p>
        </div>
      </div>

      <div className="tactical-card min-h-[500px] relative overflow-hidden flex items-center justify-center p-20">
        <div className="absolute inset-0 opacity-10">
          <svg width="100%" height="100%">
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="white" strokeWidth="0.5"/>
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>
        </div>

        <div className="relative z-10 flex flex-col items-center">
          <div className="w-32 h-32 rounded-full bg-brand/10 border-2 border-brand/40 flex items-center justify-center shadow-[0_0_50px_rgba(204,255,0,0.2)] mb-4 animate-pulse">
            <Server size={48} className="text-brand" />
          </div>
          <div className="bg-brand text-black px-4 py-1 font-black italic text-sm rounded mb-2">
            {report.target}
          </div>
          <div className="text-[9px] font-bold text-white/40 uppercase tracking-widest">审计主节点</div>

          <div className="mt-20 flex flex-wrap justify-center gap-12">
            {report.port_statuses.map((p, idx) => (
              <div key={p.port} className="flex flex-col items-center group relative">
                <div className="absolute -top-16 left-1/2 -translate-x-1/2 w-px h-16 bg-gradient-to-t from-brand/40 to-transparent group-hover:from-brand transition-all"></div>
                <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:border-brand/60 transition-all cursor-help">
                  <span className="text-xs font-black mono group-hover:text-brand">{p.port}</span>
                </div>
                <div className="mt-4 text-[9px] font-black text-white/20 uppercase tracking-tighter text-center">
                  {p.protocol}<br/>
                  <span className="text-emerald-400/60">运行中</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default TopologyView;