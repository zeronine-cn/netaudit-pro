
import { AppConfig, ScanReport, ScanMode } from '../types';

const getApiUrl = (baseUrl: string, endpoint: string): string => {
  let sanitizedBase = baseUrl.replace(/\/$/, "");
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  if (sanitizedBase.endsWith('/api') && normalizedEndpoint.startsWith('/api/')) {
    return `${sanitizedBase}${normalizedEndpoint.substring(4)}`;
  }
  return `${sanitizedBase}${normalizedEndpoint}`;
};

export const performScan = async (
  apiBaseUrl: string,
  target: string, 
  portRangeStr: string, 
  portConfig: AppConfig['ports'], 
  dicts: AppConfig['dictionaries'],
  domains: string[],
  mode: ScanMode,
  enableBrute: boolean,
  bruteProtocols: string[], // 新增参数
  onProgress: (pct: number, log: string) => void,
  abortSignal: { cancelled: boolean },
  metadata?: any 
): Promise<ScanReport> => {
  
  try {
    const startUrl = getApiUrl(apiBaseUrl, '/api/scan');
    const startResponse = await fetch(startUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        domains: domains,
        port_range: portRangeStr,
        ports_config: portConfig,
        dictionaries: dicts,
        mode: mode,
        enable_brute: enableBrute,
        brute_protocols: bruteProtocols, // 传递到后端
        metadata: metadata 
      }),
    });

    if (!startResponse.ok) {
      const errorData = await startResponse.json().catch(() => ({}));
      throw new Error(errorData.detail || `启动任务失败: ${startResponse.status}`);
    }

    const { task_id } = await startResponse.json();
    onProgress(5, "任务已同步到内核，排队中...");

    const statusUrl = getApiUrl(apiBaseUrl, `/api/scan/status/${task_id}`);
    
    const MAX_POLLS = 6000; // 增加最大轮询次数防止超时
    let polls = 0;

    while (polls < MAX_POLLS) {
      if (abortSignal.cancelled) {
        onProgress(0, "审计任务已被用户中止。");
        throw new Error("审计已取消");
      }

      const statusResponse = await fetch(statusUrl);
      if (!statusResponse.ok) throw new Error("查询任务进度时链路异常");

      const statusData = await statusResponse.json();
      
      if (statusData.status === 'completed') {
        onProgress(100, "审计完成，正在同步报告...");
        return statusData.result as ScanReport;
      }
      
      if (statusData.status === 'failed') {
        throw new Error(statusData.error || "扫描引擎异常终止");
      }

      if (statusData.progress) {
        onProgress(statusData.progress.percent || 10, statusData.progress.log || "正在探测...");
      }

      polls++;
      // 优化：将轮询间隔缩短至 250ms，大幅提升日志流畅度，配合后端微延时确保不丢日志
      await new Promise(resolve => setTimeout(resolve, 250));
    }

    throw new Error("扫描任务执行超时。");

  } catch (error: any) {
    if (error.message === "审计已取消") throw error;
    throw new Error(error.message || "审计服务异常");
  }
};
