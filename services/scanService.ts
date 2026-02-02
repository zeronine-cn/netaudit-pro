
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
  onProgress: (pct: number, log: string) => void,
  abortSignal: { cancelled: boolean },
  metadata?: any // 新增元数据参数
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
        metadata: metadata // 发送到后端
      }),
    });

    if (!startResponse.ok) {
      const errorData = await startResponse.json().catch(() => ({}));
      throw new Error(errorData.detail || `启动任务失败: ${startResponse.status}`);
    }

    const { task_id } = await startResponse.json();
    onProgress(5, "Task queued. Waiting for worker...");

    const statusUrl = getApiUrl(apiBaseUrl, `/api/scan/status/${task_id}`);
    
    // 增加最大轮询次数防止死循环，同时缩短间隔
    const MAX_POLLS = 6000; 
    let polls = 0;

    while (polls < MAX_POLLS) {
      if (abortSignal.cancelled) {
        onProgress(0, "User aborted the scan.");
        throw new Error("审计已取消");
      }

      const statusResponse = await fetch(statusUrl);
      if (!statusResponse.ok) throw new Error("Connection lost to scan engine");

      const statusData = await statusResponse.json();
      
      if (statusData.status === 'completed') {
        onProgress(100, "Scan finished. Finalizing report...");
        return statusData.result as ScanReport;
      }
      
      if (statusData.status === 'failed') {
        throw new Error(statusData.error || "Engine exited unexpectedly");
      }

      if (statusData.progress) {
        // 使用后端返回的原始日志，不加修饰
        onProgress(statusData.progress.percent || 10, statusData.progress.log || "Scanning...");
      }

      polls++;
      // 关键修改：缩短轮询时间到 300ms，让日志看起来像实时刷屏
      await new Promise(resolve => setTimeout(resolve, 300));
    }

    throw new Error("Task timed out.");

  } catch (error: any) {
    if (error.message === "审计已取消") throw error;
    throw new Error(error.message || "Unknown Service Error");
  }
};
