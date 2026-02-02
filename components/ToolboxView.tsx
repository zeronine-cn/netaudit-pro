
import React, { useState } from 'react';
import { Hash, Code, Calculator, ShieldCheck, Copy, Check, Binary, ChevronRight } from 'lucide-react';

const ToolboxView: React.FC = () => {
  const [activeTool, setActiveTool] = useState<'hash' | 'base64' | 'ip'>('hash');
  const [input, setInput] = useState('');
  const [copied, setCopied] = useState(false);

  const tools = [
    { id: 'hash', name: '哈希生成器', icon: Hash, desc: 'SHA-256 / MD5 本地计算' },
    { id: 'base64', name: 'Base64 转换', icon: Code, desc: '文本编解码处理' },
    { id: 'ip', name: '子网计算器', icon: Calculator, desc: 'IP 段与掩码划分' },
  ];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-10 animate-in fade-in duration-700">
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-5xl font-black italic uppercase tracking-tighter glow-text">战术工具箱</h2>
          <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.4em] mt-2">离线安全研发辅助套件</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* 工具选择列表 */}
        <div className="lg:col-span-1 space-y-3">
          {tools.map((tool) => (
            <button
              key={tool.id}
              onClick={() => setActiveTool(tool.id as any)}
              className={`w-full p-5 rounded-2xl border transition-all flex flex-col items-start gap-2 group ${
                activeTool === tool.id 
                  ? 'bg-brand/10 border-brand/40 text-brand' 
                  : 'bg-white/[0.02] border-white/5 text-white/40 hover:bg-white/5'
              }`}
            >
              <tool.icon size={20} className={activeTool === tool.id ? 'animate-pulse' : ''} />
              <div className="text-left">
                <div className="text-sm font-black uppercase italic tracking-tight">{tool.name}</div>
                <div className="text-[9px] font-bold opacity-40 uppercase">{tool.desc}</div>
              </div>
            </button>
          ))}
        </div>

        {/* 工具工作区 */}
        <div className="lg:col-span-3 tactical-card p-10 rounded-[2.5rem] bg-black/40 border border-white/10 min-h-[500px] flex flex-col">
          <div className="flex items-center gap-3 mb-8">
            <Binary size={24} className="text-brand" />
            <h3 className="text-xl font-black italic uppercase tracking-tighter">
              {tools.find(t => t.id === activeTool)?.name}
            </h3>
          </div>

          <div className="flex-1 space-y-8">
            <div className="space-y-4">
              <label className="text-[10px] font-black uppercase tracking-[0.3em] text-white/20 ml-1">输入原文 / 数据流</label>
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="w-full h-40 bg-white/[0.03] border border-white/10 rounded-2xl p-6 font-mono text-sm focus:border-brand/40 outline-none transition-all resize-none"
                placeholder="在此粘贴需要处理的数据..."
              />
            </div>

            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <label className="text-[10px] font-black uppercase tracking-[0.3em] text-white/20 ml-1">处理结果 (实时预览)</label>
                <button 
                  onClick={() => handleCopy("Processed Result Example")}
                  className="flex items-center gap-2 text-[9px] font-black uppercase text-brand/60 hover:text-brand transition-colors"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  {copied ? '已复制' : '复制结果'}
                </button>
              </div>
              <div className="w-full bg-brand/5 border border-brand/10 rounded-2xl p-6 font-mono text-sm text-brand/80 break-all italic">
                {input ? `[MOCK_OUTPUT] 基于离线逻辑计算所得结果...` : '等待输入数据...'}
              </div>
            </div>
          </div>

          <div className="mt-10 p-4 bg-white/[0.02] border border-white/5 rounded-xl flex items-center gap-4">
             <ShieldCheck size={18} className="text-white/20" />
             <p className="text-[10px] font-bold text-white/20 uppercase tracking-tight">
               所有计算均在浏览器沙箱本地完成，绝不向任何外部端点发送原始敏感数据。
             </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ToolboxView;
