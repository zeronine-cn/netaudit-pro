import React from 'react';
import { LayoutDashboard, Activity, ShieldAlert, FileText, Settings, ShieldCheck, Zap, LogOut } from 'lucide-react';

interface SidebarProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ currentView, setCurrentView, onLogout }) => {
  const menuItems = [
    { id: 'dashboard', label: '总览看板', icon: LayoutDashboard },
    { id: 'scan', label: '漏洞扫描', icon: Activity },
    { id: 'results', label: '风险清单', icon: ShieldAlert },
    { id: 'compliance', label: '合规映射', icon: ShieldCheck },
    { id: 'report', label: '报告中心', icon: FileText },
  ];

  return (
    <div className="w-20 lg:w-64 glass-sidebar h-screen flex flex-col fixed left-0 top-0 z-20 transition-all duration-300">
      <div className="p-6 lg:p-8">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-200">
            <Zap className="text-white w-6 h-6" />
          </div>
          <div className="hidden lg:block overflow-hidden">
            <h1 className="text-xl font-bold text-slate-800 tracking-tight font-outfit whitespace-nowrap">NetAudit Pro</h1>
            <p className="text-[10px] uppercase tracking-wider text-blue-600 font-bold">Security Edition</p>
          </div>
        </div>
      </div>
      
      <nav className="flex-1 px-4 py-4 space-y-1">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setCurrentView(item.id)}
            className={`w-full flex items-center justify-center lg:justify-start gap-3 px-4 py-3.5 rounded-xl transition-all duration-200 group ${
              currentView === item.id 
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-100' 
                : 'text-slate-500 hover:bg-white hover:text-blue-600'
            }`}
          >
            <item.icon size={20} className={currentView === item.id ? '' : 'group-hover:scale-110 transition-transform'} />
            <span className="hidden lg:block font-semibold text-sm">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="p-4 space-y-1 mb-4">
        <button 
          onClick={() => setCurrentView('settings')}
          className={`w-full flex items-center justify-center lg:justify-start gap-3 px-4 py-3 rounded-xl transition-all ${
             currentView === 'settings' ? 'text-indigo-600 bg-white shadow-sm' : 'text-slate-500 hover:bg-white/50'
          }`}
        >
          <Settings size={18} />
          <span className="hidden lg:block font-semibold text-sm">系统设置</span>
        </button>
        
        <button 
          onClick={onLogout}
          className="w-full flex items-center justify-center lg:justify-start gap-3 px-4 py-3 rounded-xl text-slate-400 hover:text-red-500 hover:bg-red-50 transition-all"
        >
          <LogOut size={18} />
          <span className="hidden lg:block font-semibold text-sm">注销登录</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;