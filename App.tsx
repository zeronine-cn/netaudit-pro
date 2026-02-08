
import React, { useState, useEffect } from 'react';
import Dock from './components/Dock';
import Dashboard from './components/Dashboard';
import ScanForm from './components/ScanForm';
import ResultsView from './components/ResultsView';
import SettingsView from './components/SettingsView';
import ComplianceView from './components/ComplianceView';
import ReportView from './components/ReportView';
import HistoryView from './components/HistoryView';
import DictWarehouseView from './components/DictWarehouseView';
import Login from './components/Login';
import TopologyView from './components/TopologyView';
import { ScanReport, AppConfig } from './types';
import { Map, ShieldCheck, Shield, Activity, HardDrive } from 'lucide-react';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentView, setCurrentView] = useState('dashboard');
  const [report, setReport] = useState<ScanReport | null>(() => {
    const saved = localStorage.getItem('last_report');
    return saved ? JSON.parse(saved) : null;
  });
  const [scanHistory, setScanHistory] = useState<ScanReport[]>([]);
  
  const [scanLogs, setScanLogs] = useState<{msg: string, type: 'info' | 'warn' | 'error' | 'success' | 'system'}[]>(() => {
    const savedLogs = localStorage.getItem('netaudit_logs');
    return savedLogs ? JSON.parse(savedLogs) : [];
  });

  const [config, setConfig] = useState<AppConfig>(() => {
    const defaultAiConfig: AppConfig['aiConfig'] = {
        provider: 'gemini',
        gemini: {
            baseUrl: '',
            apiKey: '',
            model: 'gemini-2.0-flash-exp'
        },
        custom: {
            baseUrl: 'https://api.deepseek.com/v1',
            apiKey: '',
            model: 'deepseek-chat'
        }
    };

    const defaultConfig: AppConfig = {
      apiBaseUrl: window.location.origin,
      adminPassword: 'admin888',
      ports: { 
        ssh: '22', http: '80, 8080', https: '443, 8443', dns: '53',
        mysql: '3306', redis: '6379', postgres: '5432', mongodb: '27017'
      },
      dictionaries: { 
        usernames: 'root\nadmin', 
        passwords: 'password\n123456',
        db_usernames: 'root\nadmin\npostgres\nsa',
        db_passwords: 'root\nadmin\npassword\n123456'
      },
      aiConfig: defaultAiConfig,
      defaultMetadata: {
        securityLevel: '三级',
        location: '上海金桥机房',
        evaluator: '审计员A',
        assetNamePrefix: 'SVR-'
      }
    };

    const savedConfig = localStorage.getItem('netaudit_config');
    if (savedConfig) {
        try {
            const parsed = JSON.parse(savedConfig);
            
            // 兼容性迁移：如果读取到旧版 aiConfig (扁平结构)，自动迁移到新版分层结构
            let migratedAiConfig = defaultAiConfig;
            
            if (parsed.aiConfig) {
                // 判断是否为旧版结构 (直接含有 baseUrl 字符串)
                if (typeof parsed.aiConfig.baseUrl === 'string') {
                    if (parsed.aiConfig.provider === 'custom') {
                        migratedAiConfig = {
                            ...defaultAiConfig,
                            provider: 'custom',
                            custom: {
                                baseUrl: parsed.aiConfig.baseUrl || defaultAiConfig.custom.baseUrl,
                                apiKey: parsed.aiConfig.apiKey || '',
                                model: parsed.aiConfig.model || defaultAiConfig.custom.model
                            }
                        };
                    } else {
                        migratedAiConfig = {
                            ...defaultAiConfig,
                            provider: 'gemini',
                            gemini: {
                                baseUrl: parsed.aiConfig.baseUrl || '',
                                apiKey: parsed.aiConfig.apiKey || '',
                                model: parsed.aiConfig.model || defaultAiConfig.gemini.model
                            }
                        };
                    }
                } else {
                    // 新版结构，深度合并，确保子对象存在
                    migratedAiConfig = {
                        provider: parsed.aiConfig.provider || defaultAiConfig.provider,
                        gemini: { ...defaultAiConfig.gemini, ...(parsed.aiConfig.gemini || {}) },
                        custom: { ...defaultAiConfig.custom, ...(parsed.aiConfig.custom || {}) }
                    };
                }
            }

            return {
                ...defaultConfig,
                ...parsed,
                ports: { ...defaultConfig.ports, ...(parsed.ports || {}) },
                dictionaries: { ...defaultConfig.dictionaries, ...(parsed.dictionaries || {}) },
                aiConfig: migratedAiConfig,
                defaultMetadata: { ...defaultConfig.defaultMetadata, ...(parsed.defaultMetadata || {}) }
            };
        } catch (e) {
            return defaultConfig;
        }
    }
    return defaultConfig;
  });

  // 移动 scanDraft 定义到 config 之后，以便引用 config.ports
  const [scanDraft, setScanDraft] = useState({
    target: '127.0.0.1',
    domainStr: '', 
    // 动态引用配置中的端口集
    portRange: Array.from(new Set(Object.values(config.ports).join(',').split(',').map(p => p.trim()).filter(p => p))).join(', '),
    assetName: '',
    securityLevel: '', 
    location: '',      
    evaluator: ''       
  });

  // 监听配置变化，自动更新扫描表单的端口范围
  useEffect(() => {
    const newPorts = Array.from(new Set(Object.values(config.ports).join(',').split(',').map(p => p.trim()).filter(p => p))).join(', ');
    setScanDraft(prev => ({ ...prev, portRange: newPorts }));
  }, [config.ports]);

  useEffect(() => {
    if (isAuthenticated) {
      localStorage.setItem('netaudit_config', JSON.stringify(config));
    }
  }, [config, isAuthenticated]);

  useEffect(() => {
    localStorage.setItem('netaudit_logs', JSON.stringify(scanLogs));
  }, [scanLogs]);

  const fetchHistory = async () => {
    if (!isAuthenticated) return;
    try {
      const response = await fetch(`${config.apiBaseUrl.replace(/\/$/, "")}/api/history`);
      if (response.ok) {
        const data = await response.json();
        setScanHistory(data);
      }
    } catch (e) {
      console.warn("审计引擎连接失败");
    }
  };

  useEffect(() => {
    if (isAuthenticated) fetchHistory();
  }, [isAuthenticated, config.apiBaseUrl]);

  const handleLogin = (success: boolean) => {
    if (success) setIsAuthenticated(true);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setCurrentView('dashboard');
  };

  const handleScanComplete = (newReport: ScanReport) => {
    setReport(newReport);
    localStorage.setItem('last_report', JSON.stringify(newReport));
    fetchHistory();
    setCurrentView('dashboard');
  };

  const handleSelectHistory = (selected: ScanReport) => {
    setReport(selected);
    localStorage.setItem('last_report', JSON.stringify(selected));
    setCurrentView('dashboard');
  };

  const handleDeleteHistory = (id: number) => {
    setScanHistory(prev => prev.filter(item => item.id !== id));
    if (report?.id === id) {
      setReport(null);
      localStorage.removeItem('last_report');
    }
  };

  const handleImportHistory = (imported: ScanReport[]) => {
    setScanHistory(prev => {
      const combined = [...imported, ...prev];
      const unique = combined.filter((v, i, a) => a.findIndex(t => (t.id === v.id && t.timestamp === v.timestamp)) === i);
      return unique;
    });
  };

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-black text-white font-mono selection:bg-brand selection:text-black overflow-x-hidden">
      <div className="fixed top-0 left-0 right-0 z-[60] px-8 py-4 flex justify-between items-center bg-black/40 backdrop-blur-xl border-b border-white/5">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2.5">
            <div className="w-2 h-2 rounded-full bg-brand animate-pulse"></div>
            <span className="text-[11px] font-black uppercase tracking-[0.3em] text-brand">安全节点已激活</span>
          </div>
          <div className="w-px h-4 bg-white/10"></div>
          <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-full border border-white/10">
            <HardDrive size={10} className="text-brand/60" />
            <span className="text-[8px] font-bold text-white/40 uppercase tracking-widest">Local-First Persistence Mode</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
           <button 
             onClick={() => setCurrentView('topology')} 
             className={`px-4 py-2 rounded-lg border flex items-center gap-2 transition-all group ${currentView === 'topology' ? 'bg-brand border-brand text-black shadow-[0_0_20px_rgba(204,255,0,0.2)]' : 'bg-white/5 border-white/5 hover:bg-white/10'}`}
           >
             <Map size={14} />
             <span className="text-[10px] font-black uppercase">全域拓扑</span>
           </button>
        </div>
      </div>

      <main className="pt-24 pb-40 px-6 max-w-[1400px] mx-auto animate-in fade-in duration-1000">
        {(() => {
          switch (currentView) {
            case 'dashboard': return <Dashboard report={report} scanHistory={scanHistory} onSelectReport={handleSelectHistory} />;
            case 'scan': 
              return (
                <ScanForm 
                  onScanComplete={handleScanComplete} 
                  config={config} 
                  draft={scanDraft}
                  setDraft={setScanDraft}
                  logs={scanLogs}
                  setLogs={setScanLogs}
                />
              );
            case 'history': return <HistoryView history={scanHistory} onSelect={handleSelectHistory} onDelete={handleDeleteHistory} onImport={handleImportHistory} onRefresh={fetchHistory} apiBaseUrl={config.apiBaseUrl} />;
            case 'dicts': return <DictWarehouseView config={config} setConfig={setConfig} />;
            case 'results': return <ResultsView report={report} config={config} />;
            case 'topology': return <TopologyView report={report} />;
            case 'compliance': return <ComplianceView report={report} />;
            case 'report': return <ReportView report={report} config={config} />;
            case 'settings': return <SettingsView config={config} setConfig={setConfig} />;
            default: return <Dashboard report={report} scanHistory={scanHistory} onSelectReport={handleSelectHistory} />;
          }
        })()}
      </main>
      
      <Dock currentView={currentView} setCurrentView={setCurrentView} onLogout={handleLogout} />
    </div>
  );
}

export default App;
