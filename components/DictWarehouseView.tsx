
import React, { useRef } from 'react';
import { Database, Upload, Trash2, Library, Book, Key, User, Save, Info, Zap, Shield, ChevronRight } from 'lucide-react';
import { AppConfig } from '../types';

interface DictWarehouseViewProps {
  config: AppConfig;
  setConfig: React.Dispatch<React.SetStateAction<AppConfig>>;
}

const DictWarehouseView: React.FC<DictWarehouseViewProps> = ({ config, setConfig }) => {
  const fileRef = useRef<HTMLInputElement>(null);
  const [currentKey, setCurrentKey] = React.useState<keyof AppConfig['dictionaries']>('passwords');

  // 防御性检查：确保 config 和 dictionaries 存在
  if (!config || !config.dictionaries) {
    return (
      <div className="h-[60vh] flex flex-col items-center justify-center space-y-4">
        <Library size={48} className="text-white/10 animate-pulse" />
        <p className="text-white/20 font-black uppercase tracking-widest text-xs">引擎仓库未就绪，请检查配置</p>
      </div>
    );
  }

  const handleDictChange = (key: keyof AppConfig['dictionaries'], value: string) => {
    setConfig(prev => ({
      ...prev,
      dictionaries: { ...prev.dictionaries, [key]: value }
    }));
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      handleDictChange(currentKey, content);
    };
    reader.readAsText(file);
  };

  const loadPreset = (key: keyof AppConfig['dictionaries']) => {
    const presets = {
      usernames: 'root\nadmin\nuser\nubuntu\ndebian\ntest\nsupport',
      passwords: '123456\npassword\n12345678\nadmin\n12345\n123456789\nqwerty',
      db_usernames: 'root\nadmin\npostgres\nsa\nmongodb\nreplica',
      db_passwords: 'root\nadmin\npassword\n123456\npostgres\nsa\nmongo123'
    };
    handleDictChange(key, presets[key]);
  };

  const dictCategories = [
    { id: 'usernames', label: '通用/SSH 用户名', icon: User, color: 'text-info' },
    { id: 'passwords', label: '通用/SSH 密码', icon: Key, color: 'text-brand' },
    { id: 'db_usernames', label: '数据库专有账号', icon: Database, color: 'text-orange-400' },
    { id: 'db_passwords', label: '数据库专有密码', icon: Shield, color: 'text-danger' },
  ];

  const currentDict = config.dictionaries[currentKey] || '';
  const lineCount = currentDict ? currentDict.split('\n').filter(l => l.trim()).length : 0;

  return (
    <div className="space-y-10 animate-in fade-in duration-500 pb-20">
      <div className="flex justify-between items-end border-b border-white/10 pb-6">
        <div>
          <h2 className="text-5xl font-black uppercase italic tracking-tighter glow-text">审计字典仓库</h2>
          <p className="font-bold text-brand mt-2 uppercase tracking-widest text-sm">VAULT: 用于多协议身份鉴别强度审计</p>
        </div>
        <div className="flex gap-4">
           <div className="px-4 py-2 bg-white/5 rounded-xl border border-white/10 text-[10px] font-black uppercase tracking-widest text-white/40 flex items-center gap-2">
              <Zap size={14} className="text-brand" /> 已就绪: {lineCount} 条特征
           </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
        {/* 分类导航 */}
        <div className="lg:col-span-4 space-y-4">
          {dictCategories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setCurrentKey(cat.id as any)}
              className={`w-full p-6 rounded-2xl border transition-all flex items-center gap-4 group ${
                currentKey === cat.id 
                  ? 'bg-white/5 border-brand shadow-[0_0_20px_rgba(204,255,0,0.1)]' 
                  : 'bg-black/20 border-white/5 hover:border-white/20'
              }`}
            >
              <div className={`w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center ${cat.color}`}>
                <cat.icon size={24} />
              </div>
              <div className="text-left flex-1">
                <div className={`text-sm font-black uppercase italic ${currentKey === cat.id ? 'text-white' : 'text-white/40'}`}>
                  {cat.label}
                </div>
                <div className="text-[9px] font-bold text-white/20 uppercase tracking-widest mt-1">
                  特征总量: {(config.dictionaries[cat.id as keyof AppConfig['dictionaries']] || '').split('\n').filter(l => l.trim()).length}
                </div>
              </div>
              <ChevronRight size={16} className={currentKey === cat.id ? 'text-brand' : 'text-white/10'} />
            </button>
          ))}
          
          <div className="p-8 bg-brand/5 border border-brand/10 rounded-[2.5rem] mt-10">
             <div className="flex items-center gap-3 mb-4 text-brand">
                <Info size={18} />
                <span className="text-xs font-black uppercase tracking-widest italic">等保三级基线</span>
             </div>
             <p className="text-[10px] text-white/40 leading-relaxed font-bold italic">
               等保 2.0 合规要求应对登录用户进行身份标识与鉴别。审计字典应包含：不低于 10 种常见的默认账号、常用口令及对应的弱口令特征。
             </p>
          </div>
        </div>

        {/* 编辑器区域 */}
        <div className="lg:col-span-8 tactical-card p-1 rounded-[2.5rem] bg-gradient-to-br from-white/10 to-transparent">
          <div className="bg-obsidian/95 rounded-[2.4rem] h-full flex flex-col overflow-hidden min-h-[600px]">
             <div className="p-8 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
                <div className="flex items-center gap-4">
                   <div className="w-2 h-2 rounded-full bg-brand animate-pulse"></div>
                   <h3 className="text-xl font-black italic uppercase tracking-tighter">
                      编辑特征库: <span className="text-brand">{dictCategories.find(c => c.id === currentKey)?.label}</span>
                   </h3>
                </div>
                <div className="flex gap-3">
                   <button onClick={() => loadPreset(currentKey)} className="px-5 py-2.5 bg-white/5 border border-white/10 rounded-xl text-[10px] font-black uppercase text-white/40 hover:text-white transition-all">
                      加载预设 (TOP 10)
                   </button>
                   <button onClick={() => fileRef.current?.click()} className="px-5 py-2.5 bg-brand text-black rounded-xl text-[10px] font-black uppercase flex items-center gap-2 hover:shadow-[0_0_20px_rgba(204,255,0,0.3)] transition-all">
                      <Upload size={14} /> 上传 TXT
                   </button>
                   <input type="file" ref={fileRef} className="hidden" accept=".txt" onChange={handleFileUpload} />
                </div>
             </div>
             
             <div className="flex-1 p-8 relative group">
                <textarea
                  value={currentDict}
                  onChange={(e) => handleDictChange(currentKey, e.target.value)}
                  className="w-full h-full bg-transparent font-mono text-sm text-white/80 outline-none resize-none custom-scrollbar pb-20 leading-loose"
                  placeholder="每行输入一个特征条目..."
                />
                <div className="absolute bottom-8 right-8 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
                   <Library size={120} className="text-white/5" />
                </div>
             </div>

             <div className="p-8 bg-black/40 border-t border-white/5 flex justify-between items-center">
                <div className="text-[10px] font-bold text-white/20 italic uppercase">
                  数据将实时同步至审计内核。变更后下一次任务即可生效。
                </div>
                <button onClick={() => alert('字典已持久化到本地安全存储')} className="flex items-center gap-3 px-8 py-3.5 bg-white/5 border border-white/10 rounded-2xl text-xs font-black uppercase italic hover:bg-white/10 transition-all">
                   <Save size={16} /> 保存固化
                </button>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DictWarehouseView;
