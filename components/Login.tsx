
import React, { useState, useEffect } from 'react';
import { ShieldCheck, Lock, User, ArrowRight, Zap, Loader2, KeyRound } from 'lucide-react';
import { AppConfig } from '../types';

interface LoginProps {
  onLogin: (success: boolean) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [expectedPassword, setExpectedPassword] = useState('admin888');
  const [passwordSource, setPasswordSource] = useState<'DEFAULT' | 'LOCAL' | 'SERVER'>('DEFAULT');

  useEffect(() => {
    const syncConfig = async () => {
      try {
        const response = await fetch('/api/config/security');
        if (response.ok) {
          const data = await response.json();
          if (data.expected_password) {
            setExpectedPassword(data.expected_password);
            setPasswordSource('SERVER');
            return;
          }
        }
      } catch (e) {
        console.log("后端配置同步跳过...");
      }

      const savedConfig = localStorage.getItem('netaudit_config');
      if (savedConfig) {
        try {
          const config: AppConfig = JSON.parse(savedConfig);
          if (config.adminPassword) {
            setExpectedPassword(config.adminPassword);
            setPasswordSource('LOCAL');
          }
        } catch (e) {
          console.error("无法解析本地配置");
        }
      }
    };

    syncConfig();
  }, []);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    setTimeout(() => {
      if (username === 'admin' && password === expectedPassword) {
        onLogin(true);
      } else {
        setError('鉴权失败：密钥冲突或无效令牌');
        setIsLoading(false);
      }
    }, 1200);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-8">
      <div className="w-full max-w-lg animate-in fade-in zoom-in-95 duration-1000">
        <div className="glass-card p-16 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-brand/5 blur-3xl rounded-full -translate-y-16 translate-x-16"></div>
          
          <div className="flex flex-col items-center mb-16 text-center relative z-10">
            <div className="w-24 h-24 bg-brand text-black rounded-[2.5rem] flex items-center justify-center shadow-[0_0_60px_rgba(204,255,0,0.3)] mb-10 transform rotate-12 transition-transform hover:rotate-0 duration-500">
              <KeyRound size={44} strokeWidth={2.5} />
            </div>
            <h1 className="text-6xl font-black tracking-tighter glow-text italic uppercase">审计控制台</h1>
            <p className="text-brand text-[10px] font-black tracking-[1em] mt-4 uppercase opacity-60">安全访问入口</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-8 relative z-10">
            <div className="space-y-3">
               <label className="text-[10px] font-black text-white/20 uppercase tracking-[0.5em] ml-4 block">管理员标识</label>
               <div className="relative">
                 <input
                   type="text"
                   value={username}
                   onChange={(e) => setUsername(e.target.value)}
                   className="w-full px-10 py-6 bg-white/5 border border-white/5 rounded-[2rem] text-white outline-none focus:border-brand/50 transition-all font-black mono text-center placeholder:text-white/10"
                   placeholder="输入管理员账号"
                   required
                 />
                 <User className="absolute left-6 top-1/2 -translate-y-1/2 text-white/5" size={20} />
               </div>
            </div>

            <div className="space-y-3">
               <div className="flex justify-between items-center px-4">
                 <label className="text-[10px] font-black text-white/20 uppercase tracking-[0.5em] block">安全访问令牌</label>
                 <span className="text-[8px] font-black text-white/5 uppercase italic">
                   {passwordSource === 'SERVER' ? '配置源: 预设' : 
                    passwordSource === 'LOCAL' ? '配置源: 本地' : '默认配置'}
                 </span>
               </div>
               <div className="relative">
                 <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-10 py-6 bg-white/5 border border-white/5 rounded-[2rem] text-white outline-none focus:border-brand/50 transition-all font-black mono text-center placeholder:text-white/10"
                    placeholder="输入访问密钥"
                    required
                  />
                  <Lock className="absolute left-6 top-1/2 -translate-y-1/2 text-white/5" size={20} />
               </div>
            </div>

            {error && (
              <div className="p-4 bg-danger/10 border border-danger/20 rounded-xl text-danger text-[10px] font-black uppercase text-center tracking-widest animate-shake">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className={`w-full py-7 rounded-[2.5rem] flex items-center justify-center gap-4 text-xl uppercase italic tracking-tighter transition-all ${
                isLoading 
                ? 'bg-white/5 text-white/20 cursor-wait' 
                : 'bg-brand text-black hover:shadow-[0_0_40px_rgba(204,255,0,0.4)] active:scale-[0.98]'
              }`}
            >
              {isLoading ? (
                <Loader2 className="animate-spin" size={28} />
              ) : (
                <>建立安全连接会话 <ArrowRight size={24} strokeWidth={3} /></>
              )}
            </button>
          </form>

          <div className="mt-16 flex justify-between items-center text-[8px] font-black text-white/10 tracking-[0.3em] uppercase">
            <span>安全防护等级: 三级</span>
            <div className="flex gap-1">
              <div className="w-1 h-1 rounded-full bg-brand/40"></div>
              <div className="w-1 h-1 rounded-full bg-brand/20"></div>
              <div className="w-1 h-1 rounded-full bg-brand/10"></div>
            </div>
            <span>合规性评估模式</span>
          </div>
        </div>
        
        <p className="mt-8 text-center text-[10px] font-black text-white/5 uppercase tracking-[0.8em]">系统内核版本 v3.1.0-STABLE</p>
      </div>
    </div>
  );
};

export default Login;
