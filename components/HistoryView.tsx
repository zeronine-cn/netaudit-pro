
import React, { useState, useRef } from 'react';
import { ScanReport } from '../types';
import { Database, Search, Calendar, Target, Trash2, ExternalLink, Download, Upload, Loader2, RefreshCw, Bomb, Eraser } from 'lucide-react';

interface HistoryViewProps {
  history: ScanReport[];
  onSelect: (report: ScanReport) => void;
  onDelete: (id: number) => void;
  onImport?: (reports: ScanReport[]) => void;
  onRefresh?: () => void;
  apiBaseUrl: string;
}

const HistoryView: React.FC<HistoryViewProps> = ({ history, onSelect, onDelete, onImport, onRefresh, apiBaseUrl }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [isPurging, setIsPurging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filteredHistory = history.filter(item => 
    item.target.includes(searchTerm) || item.timestamp.includes(searchTerm)
  );

  const handleExportDB = () => {
    const dataStr = JSON.stringify(history, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `NetAudit_Full_Backup_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
  };

  const handleImportDB = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const imported = JSON.parse(event.target?.result as string);
        if (Array.isArray(imported)) {
          if (onImport) onImport(imported);
          alert(`成功导入 ${imported.length} 条审计记录。`);
        } else {
          alert('数据格式不兼容，请导入有效的审计 JSON 数组。');
        }
      } catch (e) {
        alert('文件解析失败，请确保导入的是有效的 JSON 档案文件。');
      }
      // 清空 input 方便下次选择同名文件
      if (fileInputRef.current) fileInputRef.current.value = '';
    };
    reader.readAsText(file);
  };

  const handlePurgeAll = async () => {
    if (!confirm('🚨 警告：此操作将从数据库清空【所有】记录。是否确认执行后端删除？')) return;
    
    setIsPurging(true);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const response = await fetch(`${base}/api/history/purge`, {
        method: 'DELETE',
        headers: { 'Accept': 'application/json' }
      });
      if (response.ok) {
        if (onRefresh) onRefresh();
        localStorage.removeItem('last_report');
        alert('后端数据库已清空。');
      } else {
        const err = await response.json();
        alert(`清空失败: ${err.detail || response.status}`);
      }
    } catch (e) {
      alert('清空失败：连接异常，请检查后端引擎是否在运行。');
    } finally {
      setIsPurging(false);
    }
  };

  const resetLocalCache = () => {
    if (!confirm('该操作将重置前端显示状态，清除浏览器本地缓存。不影响数据库。')) return;
    localStorage.removeItem('last_report');
    if (onRefresh) onRefresh();
    window.location.reload();
  };

  const handleDelete = async (id: number) => {
    if (!confirm('确定要永久销毁该审计档案吗？此操作不可逆。')) return;
    
    setDeletingId(id);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const url = `${base}/api/history/${id}`;
      
      const response = await fetch(url, {
        method: 'DELETE',
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.ok || response.status === 404) {
        onDelete(id);
      } else {
        onDelete(id); 
      }
    } catch (e) {
      onDelete(id);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-700">
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div className="flex-1">
          <h2 className="text-5xl font-black uppercase italic tracking-tighter glow-text">审计档案库</h2>
          <div className="flex flex-wrap items-center gap-y-4 gap-x-6 mt-4">
            <p className="font-bold text-white/20 uppercase tracking-widest text-sm italic">资产持久化仓储</p>
            <div className="h-4 w-px bg-white/10 hidden md:block"></div>
            
            <div className="flex items-center gap-4">
              <button onClick={onRefresh} className="flex items-center gap-1.5 text-[10px] font-black text-info hover:text-white transition-all uppercase">
                <RefreshCw size={12} /> 同步数据
              </button>
              <button onClick={handleExportDB} className="flex items-center gap-1.5 text-[10px] font-black text-brand hover:text-white transition-all uppercase">
                <Download size={12} /> 导出备份
              </button>
              
              {/* 找回的导入功能 */}
              <button 
                onClick={() => fileInputRef.current?.click()} 
                className="flex items-center gap-1.5 text-[10px] font-black text-indigo-400 hover:text-white transition-all uppercase"
              >
                <Upload size={12} /> 导入备份
              </button>
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleImportDB} 
                className="hidden" 
                accept=".json" 
              />
            </div>

            <div className="h-4 w-px bg-white/10 hidden md:block"></div>

            <div className="flex items-center gap-4">
              <button onClick={resetLocalCache} className="flex items-center gap-1.5 text-[10px] font-black text-white/20 hover:text-white transition-all uppercase">
                <Eraser size={12} /> 重置本地
              </button>
              <button onClick={handlePurgeAll} disabled={isPurging} className="flex items-center gap-1.5 text-[10px] font-black text-danger hover:text-white transition-all uppercase">
                {isPurging ? <Loader2 size={12} className="animate-spin" /> : <Bomb size={12} />} 彻底销毁所有
              </button>
            </div>
          </div>
        </div>
        
        <div className="relative w-72 mb-1">
           <input 
             type="text"
             value={searchTerm}
             onChange={(e) => setSearchTerm(e.target.value)}
             placeholder="搜索资产或时间..."
             className="w-full bg-white/5 border border-white/10 rounded-xl px-12 py-3 text-xs font-bold outline-none focus:border-brand/50 transition-all"
           />
           <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20" />
        </div>
      </div>

      {filteredHistory.length === 0 ? (
        <div className="tactical-card p-24 text-center rounded-[3rem] border-dashed border border-white/10">
           <Database size={48} className="text-white/5 mx-auto mb-6" />
           <p className="text-white/20 font-black uppercase tracking-widest text-xs">档案库暂无记录</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredHistory.map((item) => (
            <div key={`${item.id}-${item.timestamp}`} className="tactical-card group overflow-hidden rounded-2xl border border-white/5 hover:border-white/10 transition-all flex items-center p-6 gap-8">
              <div className={`w-16 h-16 rounded-xl flex flex-col items-center justify-center shrink-0 shadow-lg ${item.score > 80 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : item.score > 60 ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                <span className="text-2xl font-black italic">{item.score}</span>
                <span className="text-[8px] font-bold uppercase tracking-tighter">SCORE</span>
              </div>

              <div className="flex-1 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                 <div>
                    <div className="text-[9px] font-black text-white/20 uppercase tracking-widest mb-1 flex items-center gap-2">
                       <Target size={10} /> 探测目标
                    </div>
                    <div className="text-lg font-black mono text-white/80">{item.target}</div>
                 </div>
                 <div>
                    <div className="text-[9px] font-black text-white/20 uppercase tracking-widest mb-1 flex items-center gap-2">
                       <Calendar size={10} /> 审计时间
                    </div>
                    <div className="text-sm font-bold text-white/40">{item.timestamp}</div>
                 </div>
                 <div className="flex items-center gap-4">
                    <div className="flex -space-x-2">
                       {item.summary.high > 0 && <div className="w-8 h-8 rounded-full bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-500 font-black text-[10px]" title="高危">{item.summary.high}</div>}
                       <div className="w-8 h-8 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-white/40 font-black text-[10px]">{item.defects.length}</div>
                    </div>
                 </div>
              </div>

              <div className="flex items-center gap-3">
                 <button 
                   onClick={() => onSelect(item)}
                   className="px-5 py-2.5 bg-brand text-black rounded-lg font-black text-[10px] uppercase italic flex items-center gap-2 hover:shadow-[0_0_20px_rgba(204,255,0,0.3)] transition-all"
                 >
                   <ExternalLink size={12} strokeWidth={3} /> 查看详情
                 </button>
                 <button 
                   onClick={() => item.id !== undefined && handleDelete(item.id)}
                   disabled={deletingId === item.id}
                   className="p-3 bg-white/5 text-white/20 hover:text-red-500 hover:bg-red-500/10 rounded-xl transition-all border border-transparent hover:border-red-500/20"
                   title="永久删除此档案"
                 >
                   {deletingId === item.id ? <Loader2 size={16} className="animate-spin" /> : <Trash2 size={18} />}
                 </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default HistoryView;
