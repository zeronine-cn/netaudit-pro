
import React, { useRef, useState } from 'react';
import { Save, RefreshCw, Upload, Info, Cpu, Database, Network, ShieldEllipsis, Lock, FileText, CheckCircle2, AlertCircle, Loader2, Zap, BrainCircuit, Sparkles, KeyRound, ShieldAlert, ShieldCheck, Eye, EyeOff } from 'lucide-react';
import { AppConfig } from '../types';

interface SettingsViewProps {
  config: AppConfig;
  setConfig: React.Dispatch<React.SetStateAction<AppConfig>>;
}

const SettingsView: React.FC<SettingsViewProps> = ({ config, setConfig }) => {
  const userFileRef = useRef<HTMLInputElement>(null);
  const passFileRef = useRef<HTMLInputElement>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{status: 'idle' | 'success' | 'error', msg: string}>({status: 'idle', msg: ''});

  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [pwdForm, setPwdForm] = useState({ old: '', new: '', confirm: '' });
  const [pwdError, setPwdError] = useState('');
  const [pwdSuccess, setPwdSuccess] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);

  const handlePortChange = (key: keyof AppConfig['ports'], value: string) => {
    setConfig(prev => ({
      ...prev,
      ports: { ...prev.ports, [key]: value }
    }));
  };

  const handleDictChange = (key: keyof AppConfig['dictionaries'], value: string) => {
    setConfig(prev => ({
      ...prev,
      dictionaries: { ...prev.dictionaries, [key]: value }
    }));
  };

  const handleAiConfigChange = (key: keyof AppConfig['aiConfig'], value: any) => {
    setConfig(prev => ({
      ...prev,
      aiConfig: { ...prev.aiConfig, [key]: value }
    }));
  };

  const loadPreset = (loadType: 'usernames' | 'passwords') => {
    const presets = {
      usernames: 'root\nadmin\nuser\nubuntu\ndebian\ntest\nsupport\noperator\nmanager\nwebmaster',
      passwords: '123456\npassword\n12345678\nadmin\n12345\n123456789\n1234\nqwerty\npassword123\nadmin123'
    };
    handleDictChange(loadType, presets[loadType]);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>, fileKey: keyof AppConfig['dictionaries']) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      handleDictChange(fileKey, content);
    };
    reader.readAsText(file);
  };

  const testConnection = async () => {
    setIsTesting(true);
    setTestResult({status: 'idle', msg: ''});
    try {
      const baseUrl = config.apiBaseUrl.replace(/\/$/, "");
      const res = await fetch(`${baseUrl}/api/history`, { method: 'GET' });
      if (res.ok) {
        setTestResult({status: 'success', msg: '审计引擎在线 (v3.1 STABLE)'});
      } else {
        setTestResult({status: 'error', msg: `连接拒绝: HTTP ${res.status}`});
      }
    } catch (e) {
      setTestResult({status: 'error', msg: '无法连接到后端引擎，请检查 CORS 或 URL'});
    } finally {
      setIsTesting(false);
    }
  };

  const executePasswordChange = () => {
    setPwdError('');
    if (pwdForm.old !== config.adminPassword) {
      setPwdError('身份验证失败：输入的旧令牌与系统记录不符。');
      return;
    }
    if (pwdForm.new.length < 6) {
      setPwdError('操作拒绝：新令牌强度不足（需至少 6 位）。');
      return;
    }
    if (pwdForm.new !== pwdForm.confirm) {
      setPwdError('一致性校验失败：两次输入的新令牌内容不匹配。');
      return;
    }
    setConfig(prev => ({ ...prev, adminPassword: pwdForm.new }));
    setPwdSuccess(true);
    setPwdForm({ old: '', new: '', confirm: '' });
    setTimeout(() => {
      setPwdSuccess(false);
      setIsChangingPassword(false);
    }, 2000);
  };

  return (
    <div className="space-y-10 animate-in fade-in duration-500 pb-20 max-w-[1400px] mx-auto px-4">
      <div className="flex justify-between items-end border-b border-white/10 pb-6">
        <div>
          <h2 className="text-5xl font-black uppercase italic tracking-tighter glow-text">审计引擎核心</h2>
          <p className="font-bold text-brand mt-2 uppercase tracking-widest text-sm">全局扫描与字典参数配置</p>
        </div>
        <button 
            onClick={() => {
                if(confirm('警告：此操作将清除所有当前配置并恢复到出厂状态。是否继续？')) {
                    setConfig({
                        apiBaseUrl: window.location.origin,
                        adminPassword: 'admin888',
                        ports: { ssh: '22', http: '80, 8080', https: '443, 8443', dns: '53' },
                        dictionaries: { usernames: 'root\nadmin', passwords: 'password\n123456' },
                        aiConfig: {
                          provider: 'gemini',
                          baseUrl: 'https://api.google.com',
                          apiKey: '',
                          model: 'gemini-3-pro-preview'
                        }
                    });
                    localStorage.removeItem('netaudit_config');
                    window.location.reload();
                }
            }}
            className="px-6 py-3 bg-white/5 border border-white/10 text-white/40 text-[10px] font-black uppercase tracking-widest rounded-xl hover:bg-red-500 hover:text-white hover:border-red-500 transition-all"
        >
            工厂重置
        </button>
      </div>

      <div className="grid grid-cols-1 gap-10">
        
        {/* 通信链路配置 */}
        <div className="tactical-card p-10 rounded-[2.5rem] border-l-8 border-l-brand relative overflow-hidden bg-black/40">
           <div className="absolute top-0 left-0 w-2 h-full bg-brand opacity-20"></div>
           <h3 className="text-3xl font-black italic uppercase mb-8 flex items-center gap-5">
            <Network size={36} className="text-brand drop-shadow-[0_0_8px_rgba(204,255,0,0.5)]" />
            引擎通信链路
          </h3>
          <div className="space-y-6">
            <label className="block text-[10px] font-black uppercase tracking-[0.4em] text-white/20 ml-1">后端 API 基础路径 (BASE URL)</label>
            <div className="flex flex-col sm:flex-row gap-4">
              <input 
                type="text" 
                value={config.apiBaseUrl}
                onChange={(e) => setConfig(prev => ({...prev, apiBaseUrl: e.target.value}))}
                className="flex-1 px-8 py-6 bg-white/[0.03] border border-white/10 rounded-2xl text-brand font-bold mono focus:border-brand outline-none transition-all shadow-inner text-xl"
                placeholder="https://engine-api.secure-node.io"
              />
              <button 
                onClick={testConnection}
                disabled={isTesting}
                className="px-10 h-[72px] bg-brand text-black rounded-2xl font-black uppercase italic text-sm hover:shadow-[0_0_30px_rgba(204,255,0,0.4)] transition-all flex items-center justify-center gap-3 active:scale-95"
              >
                {isTesting ? <Loader2 className="animate-spin" size={20} /> : <RefreshCw size={20} />}
                探测链路
              </button>
            </div>
            {testResult.status !== 'idle' && (
              <div className={`mt-2 flex items-center gap-3 font-black text-[10px] uppercase p-4 rounded-xl border ${testResult.status === 'success' ? 'bg-brand/10 border-brand/20 text-brand' : 'bg-danger/10 border-danger/20 text-danger'}`}>
                 {testResult.status === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                 {testResult.msg}
              </div>
            )}
          </div>
        </div>

        {/* 凭据管理模块 */}
        <div className="tactical-card p-10 rounded-[2.5rem] border-l-8 border-l-danger bg-danger/5 relative overflow-hidden bg-black/40">
           <div className="absolute top-0 left-0 w-2 h-full bg-danger opacity-20"></div>
           <div className="flex flex-col xl:flex-row justify-between items-start xl:items-center gap-10">
              <div className="flex items-center gap-6">
                 <div className="w-20 h-20 bg-danger/20 rounded-3xl flex items-center justify-center text-danger border border-danger/20 shadow-[0_0_30px_rgba(255,0,76,0.1)]">
                    <ShieldAlert size={40} />
                 </div>
                 <div>
                    <h3 className="text-3xl font-black italic uppercase text-white/90">准入凭据维护</h3>
                    <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.3em] mt-2 leading-relaxed">控制台准入令牌变更（三步验证模式）</p>
                 </div>
              </div>
              
              {!isChangingPassword ? (
                 <div className="flex flex-col sm:flex-row items-center gap-8 w-full xl:w-auto">
                   <div className="text-right hidden lg:block opacity-40">
                     <span className="text-[9px] font-black text-white uppercase tracking-widest block mb-1">当前生效令牌</span>
                     <span className="font-mono text-white italic font-bold">已加密隐藏</span>
                   </div>
                   <button 
                     onClick={() => setIsChangingPassword(true)}
                     className="w-full xl:w-auto px-12 py-6 bg-danger text-white rounded-2xl font-black uppercase italic text-sm hover:shadow-[0_0_40px_rgba(255,0,76,0.4)] transition-all flex items-center gap-4 justify-center active:scale-95"
                   >
                     <KeyRound size={24} />
                     进入令牌变更流程
                   </button>
                 </div>
              ) : (
                 <div className="flex-1 w-full bg-black/60 p-8 rounded-[2.5rem] border border-white/5 animate-in slide-in-from-right-4 duration-300">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                       <input 
                         type="password" 
                         value={pwdForm.old}
                         onChange={e => setPwdForm({...pwdForm, old: e.target.value})}
                         className="w-full px-6 py-5 bg-white/5 border border-white/10 rounded-2xl text-white font-mono text-xs focus:border-danger outline-none"
                         placeholder="验证当前旧令牌"
                       />
                       <input 
                         type="text" 
                         value={pwdForm.new}
                         onChange={e => setPwdForm({...pwdForm, new: e.target.value})}
                         className="w-full px-6 py-5 bg-white/5 border border-white/10 rounded-2xl text-brand font-mono text-xs focus:border-brand outline-none"
                         placeholder="设定新访问令牌"
                       />
                       <input 
                         type="text" 
                         value={pwdForm.confirm}
                         onChange={e => setPwdForm({...pwdForm, confirm: e.target.value})}
                         className="w-full px-6 py-5 bg-white/5 border border-white/10 rounded-2xl text-brand font-mono text-xs focus:border-brand outline-none"
                         placeholder="重复输入新令牌"
                       />
                    </div>
                    {pwdError && <div className="mb-6 text-danger text-[10px] font-black uppercase text-center flex items-center justify-center gap-2 animate-shake"><AlertCircle size={14} /> {pwdError}</div>}
                    {pwdSuccess && <div className="mb-6 text-brand text-[10px] font-black uppercase text-center flex items-center justify-center gap-2"><ShieldCheck size={16} /> 令牌同步成功</div>}
                    <div className="flex gap-4">
                       <button onClick={executePasswordChange} disabled={pwdSuccess} className="flex-1 py-5 bg-brand text-black rounded-2xl font-black uppercase italic text-sm hover:shadow-[0_0_20px_rgba(204,255,0,0.3)] transition-all">同步并固化变更</button>
                       <button onClick={() => setIsChangingPassword(false)} className="px-10 py-5 bg-white/5 text-white/40 rounded-2xl font-black uppercase italic text-xs">放弃操作</button>
                    </div>
                 </div>
              )}
           </div>
        </div>

        {/* AI 专家审计核心 */}
        <div className="tactical-card p-10 rounded-[2.5rem] border-l-8 border-l-indigo-500 col-span-1 bg-indigo-500/5 relative overflow-hidden bg-black/40 shadow-2xl">
          <div className="absolute top-0 left-0 w-2 h-full bg-indigo-500 opacity-20"></div>
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-10">
            <h3 className="text-3xl font-black italic uppercase flex items-center gap-5 text-indigo-400">
              <BrainCircuit size={40} className="drop-shadow-[0_0_10px_rgba(129,140,248,0.5)]" />
              AI 专家审计核心 (SECURE MODE)
            </h3>
            <div className="flex bg-white/5 p-1 rounded-2xl border border-white/10 self-stretch md:self-auto">
               <button 
                 onClick={() => handleAiConfigChange('provider', 'gemini')}
                 className={`flex-1 px-6 py-3 rounded-xl text-[10px] font-black uppercase transition-all flex items-center justify-center gap-3 ${config.aiConfig.provider === 'gemini' ? 'bg-indigo-600 text-white shadow-lg' : 'text-white/40 hover:text-white'}`}
               >
                 <Sparkles size={14} /> GEMINI
               </button>
               <button 
                 onClick={() => handleAiConfigChange('provider', 'custom')}
                 className={`flex-1 px-6 py-3 rounded-xl text-[10px] font-black uppercase transition-all flex items-center justify-center gap-3 ${config.aiConfig.provider === 'custom' ? 'bg-indigo-600 text-white shadow-lg' : 'text-white/40 hover:text-white'}`}
               >
                 <ShieldEllipsis size={14} /> 自定义接口
               </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="space-y-4">
              <label className="block text-[11px] font-black uppercase tracking-[0.4em] text-white/20 ml-1">调用模型 (MODEL ID)</label>
              <input 
                type="text" 
                value={config.aiConfig.model}
                onChange={(e) => handleAiConfigChange('model', e.target.value)}
                className="w-full px-6 py-5 bg-black/40 border border-white/10 rounded-2xl text-white font-bold mono focus:border-indigo-500 outline-none transition-all shadow-inner"
                placeholder="gemini-3-pro-preview"
              />
            </div>

            <div className="space-y-4">
              <label className="block text-[11px] font-black uppercase tracking-[0.4em] text-white/20 ml-1">接口地址 (ENDPOINT)</label>
              <input 
                type="text" 
                value={config.aiConfig.baseUrl}
                onChange={(e) => handleAiConfigChange('baseUrl', e.target.value)}
                className="w-full px-6 py-5 bg-black/40 border border-white/10 rounded-2xl text-white font-bold mono focus:border-indigo-500 outline-none transition-all shadow-inner"
                placeholder="https://api.google.com"
              />
            </div>

            <div className="space-y-4">
              <label className="block text-[11px] font-black uppercase tracking-[0.4em] text-white/20 ml-1">API 访问令牌 (API KEY)</label>
              <div className="relative group">
                <input 
                  type={showApiKey ? "text" : "password"}
                  value={config.aiConfig.apiKey || ''}
                  onChange={(e) => handleAiConfigChange('apiKey', e.target.value)}
                  className="w-full px-6 py-5 bg-black/40 border border-white/10 rounded-2xl text-brand font-bold mono focus:border-indigo-500 outline-none transition-all shadow-inner"
                  placeholder="手动输入审计密钥..."
                />
                <button 
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-6 top-1/2 -translate-y-1/2 text-white/20 hover:text-brand transition-colors"
                >
                  {showApiKey ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>

            <div className="md:col-span-3 p-8 bg-indigo-500/10 rounded-3xl border border-indigo-500/20 backdrop-blur-md">
               <div className="flex items-center gap-5">
                  <Info className="text-indigo-400 shrink-0" size={24} />
                  <p className="text-[11px] font-bold text-indigo-200/50 uppercase tracking-[0.1em] italic leading-relaxed">
                    安全说明：API 鉴权已支持手动填写（BYOK 模式）。若此项为空，系统将尝试调用底层安全底座（process.env.API_KEY）自动注入。
                    {config.aiConfig.provider === 'custom' ? " 您只需配置对应的 Endpoint，系统会自动带上自定义授权令牌。" : " 此模式下直接与 Google 审计服务器建立链路，数据传输全程加密。"}
                  </p>
               </div>
            </div>
          </div>
        </div>

        {/* 下方的端口和字典保持原样 */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
          <div className="tactical-card p-10 rounded-[2.5rem] border-l-8 border-l-info bg-black/40">
            <h3 className="text-3xl font-black italic uppercase mb-10 flex items-center gap-5">
              <Cpu size={36} className="text-info" />
              资产端口拓扑
            </h3>
            <div className="space-y-8">
              {Object.entries(config.ports).map(([portType, portVal]) => (
                  <div key={portType} className="space-y-4">
                    <label className="block text-[11px] font-bold uppercase tracking-[0.4em] text-white/20 ml-1">{portType.toUpperCase()} 协议端口标识</label>
                    <input 
                      type="text" 
                      value={portVal}
                      onChange={(e) => handlePortChange(portType as keyof AppConfig['ports'], e.target.value)}
                      className="w-full px-8 py-5 bg-white/5 border border-white/10 rounded-2xl text-white font-bold mono focus:border-info outline-none transition-all"
                    />
                  </div>
              ))}
            </div>
          </div>

          <div className="tactical-card p-10 rounded-[2.5rem] border-l-8 border-l-brand bg-black/40">
            <h3 className="text-3xl font-black italic uppercase mb-10 flex items-center gap-5">
              <Database size={36} className="text-brand" />
              认证字典仓库
            </h3>
            <div className="space-y-12">
              {[
                { dictKey: 'usernames', dictLabel: '管理员用户名', dictRef: userFileRef },
                { dictKey: 'passwords', dictLabel: '安全策略密码', dictRef: passFileRef }
              ].map((dictItem) => (
                  <div key={dictItem.dictKey} className="space-y-5">
                    <div className="flex justify-between items-center px-1">
                      <label className="block text-[11px] font-bold uppercase tracking-[0.3em] text-white/20">{dictItem.dictLabel} 集合库</label>
                      <div className="flex gap-3">
                        <button onClick={() => loadPreset(dictItem.dictKey as any)} className="px-4 py-2 bg-white/10 rounded-xl text-[10px] font-black text-white/60 uppercase hover:bg-white/20 transition-all">预设 TOP 10</button>
                        <button onClick={() => dictItem.dictRef.current?.click()} className="px-4 py-2 bg-brand/10 rounded-xl text-[10px] font-black text-brand uppercase hover:bg-brand hover:text-black transition-all">上传 TXT</button>
                      </div>
                      <input type="file" ref={dictItem.dictRef} className="hidden" accept=".txt" onChange={(e) => handleFileUpload(e, dictItem.dictKey as any)} />
                    </div>
                    <textarea 
                      rows={6}
                      value={config.dictionaries[dictItem.dictKey as keyof AppConfig['dictionaries']]}
                      onChange={(e) => handleDictChange(dictItem.dictKey as keyof AppConfig['dictionaries'], e.target.value)}
                      className="w-full p-8 bg-black/20 border border-white/5 rounded-[2.5rem] text-white/80 font-mono text-xs h-[180px] focus:border-brand outline-none transition-all resize-none shadow-inner custom-scrollbar"
                    />
                  </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      
      <div className="tactical-card p-12 rounded-[4rem] bg-brand/5 border-brand/20 flex flex-col md:flex-row items-center gap-10 shadow-[0_0_100px_rgba(204,255,0,0.05)] backdrop-blur-md">
         <div className="w-24 h-24 bg-brand text-black rounded-[2.5rem] flex items-center justify-center shrink-0 shadow-2xl transform hover:rotate-6 transition-transform">
            <Save size={48} strokeWidth={2.5} />
         </div>
         <div className="flex-1 text-center md:text-left">
            <div className="text-4xl font-black uppercase italic leading-none mb-4 glow-text text-brand">全域配置已实时持久化</div>
            <p className="font-bold text-white/40 uppercase tracking-tight italic text-sm">资产拓扑、准入凭据以及 AI 审计引擎参数已安全归档至本地节点，下一次审计会话将自动应用生效。</p>
         </div>
      </div>
    </div>
  );
};

export default SettingsView;
