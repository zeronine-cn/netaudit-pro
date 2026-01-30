
import React, { useState, useRef, useEffect } from 'react';
import { LayoutDashboard, Compass, ShieldAlert, ShieldCheck, FileText, Settings, LogOut, Terminal, GripVertical, ChevronLeft, Map, Archive } from 'lucide-react';

interface DockProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  onLogout: () => void;
}

const Dock: React.FC<DockProps> = ({ currentView, setCurrentView, onLogout }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStartPos = useRef({ x: 0, y: 0 });
  const mouseMoved = useRef(false);
  const dockRef = useRef<HTMLDivElement>(null);

  const menuItems = [
    { id: 'dashboard', label: '全景概览', icon: LayoutDashboard },
    { id: 'scan', label: '审计任务', icon: Compass },
    { id: 'topology', label: '资产拓扑', icon: Map },
    { id: 'history', label: '档案库', icon: Archive },
    { id: 'results', label: '缺陷发现', icon: ShieldAlert },
    { id: 'compliance', label: '等保对齐', icon: ShieldCheck },
    { id: 'report', label: '导出终端', icon: FileText },
    { id: 'settings', label: '引擎配置', icon: Settings },
  ];

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    mouseMoved.current = false;
    dragStartPos.current = {
      x: e.clientX - position.x,
      y: e.clientY - position.y
    };
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      if (Math.abs(e.clientX - (dragStartPos.current.x + position.x)) > 5 || 
          Math.abs(e.clientY - (dragStartPos.current.y + position.y)) > 5) {
        mouseMoved.current = true;
      }
      const newX = e.clientX - dragStartPos.current.x;
      const newY = e.clientY - dragStartPos.current.y;
      setPosition({ x: newX, y: newY });
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
    }

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging, position]);

  const handleToggleCollapse = (e: React.MouseEvent) => {
    if (!mouseMoved.current) {
      setIsCollapsed(false);
    }
  };

  return (
    <div 
      ref={dockRef}
      className={`fixed bottom-10 left-1/2 -translate-x-1/2 z-50 transition-transform duration-75 ease-out ${isDragging ? 'scale-[1.05]' : ''}`}
      style={{ 
        transform: `translate(calc(-50% + ${position.x}px), ${position.y}px)`,
      }}
    >
      <div className={`tactical-card flex items-center shadow-2xl border-white/10 ring-1 ring-white/5 bg-black/90 backdrop-blur-3xl transition-all duration-500 overflow-hidden ${isCollapsed ? 'w-16 h-16 rounded-full px-0 py-0 cursor-grab active:cursor-grabbing' : 'px-2 py-2 rounded-2xl border border-white/5'}`}>
        
        {!isCollapsed && (
          <div 
            onMouseDown={handleMouseDown}
            className="px-2 cursor-grab active:cursor-grabbing hover:bg-white/5 rounded-l-xl py-4 transition-colors group"
          >
            <GripVertical size={16} className="text-white/10 group-hover:text-brand" />
          </div>
        )}

        <div 
          onMouseDown={isCollapsed ? handleMouseDown : undefined}
          onClick={isCollapsed ? handleToggleCollapse : undefined}
          className={`flex items-center justify-center shrink-0 transition-all duration-500 ${isCollapsed ? 'w-full h-full relative' : 'px-3 border-r border-white/5'}`}
        >
          <div className={`rounded-lg bg-brand flex items-center justify-center shadow-[0_0_25px_rgba(204,255,0,0.5)] ${isCollapsed ? 'w-10 h-10' : 'w-8 h-8'}`}>
            <Terminal size={isCollapsed ? 20 : 16} className="text-black" />
          </div>
        </div>
        
        {!isCollapsed && (
          <div className="flex items-center gap-1 px-1">
            {menuItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentView(item.id)}
                className={`p-3 min-w-[76px] flex flex-col items-center gap-1 rounded-xl transition-all relative group ${
                  currentView === item.id 
                    ? 'bg-brand/10 text-brand font-black' 
                    : 'text-white/30 hover:text-white hover:bg-white/5'
                }`}
              >
                {currentView === item.id && (
                  <div className="absolute inset-0 bg-brand/5 blur-xl rounded-xl animate-pulse"></div>
                )}
                <item.icon size={20} strokeWidth={currentView === item.id ? 2.5 : 2} className="relative z-10" />
                <span className="text-[10px] font-black tracking-tighter relative z-10">
                  {item.label}
                </span>
              </button>
            ))}
            
            <div className="w-[1px] h-6 bg-white/5 mx-1"></div>
            
            <button 
              onClick={onLogout}
              className="p-3 flex flex-col items-center gap-1 text-danger/40 hover:text-danger hover:bg-danger/10 rounded-xl transition-all"
            >
              <LogOut size={20} />
              <span className="text-[10px] font-black tracking-tighter">注销</span>
            </button>
          </div>
        )}

        {!isCollapsed && (
          <button 
            onClick={() => setIsCollapsed(true)}
            className="ml-1 p-2 text-white/10 hover:text-brand hover:bg-white/5 rounded-r-xl transition-all h-full flex items-center"
          >
            <ChevronLeft size={16} />
          </button>
        )}
      </div>
    </div>
  );
};

export default Dock;
