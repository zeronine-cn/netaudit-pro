import { AppConfig, ScanReport } from '../types';

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
  domains: string[]
): Promise<ScanReport> => {
  
  try {
    // 1. 发起异步扫描任务
    const startUrl = getApiUrl(apiBaseUrl, '/api/scan');
    const startResponse = await fetch(startUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        domains: domains,
        port_range: portRangeStr,
        ports_config: portConfig,
        dictionaries: dicts
      }),
    });

    if (!startResponse.ok) {
      const errorData = await startResponse.json().catch(() => ({}));
      throw new Error(errorData.detail || `启动任务失败: ${startResponse.status}`);
    }

    const { task_id } = await startResponse.json();
    console.log(`扫描任务已下发，ID: ${task_id}`);

    // 2. 开始轮询状态
    const statusUrl = getApiUrl(apiBaseUrl, `/api/scan/status/${task_id}`);
    
    // 最大尝试次数：针对大字典，设为 600 次 (每次 2 秒，共 20 分钟)
    const MAX_POLLS = 600;
    let polls = 0;

    while (polls < MAX_POLLS) {
      const statusResponse = await fetch(statusUrl);
      if (!statusResponse.ok) throw new Error("查询任务进度时链路异常");

      const statusData = await statusResponse.json();
      
      if (statusData.status === 'completed') {
        return statusData.result as ScanReport;
      }
      
      if (statusData.status === 'failed') {
        throw new Error(statusData.error || "扫描引擎后台执行出错");
      }

      // 继续等待
      polls++;
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    throw new Error("扫描任务执行时间超过 20 分钟限制，请减小字典规模。");

  } catch (error: any) {
    throw new Error(error.message || "审计服务异常");
  }
};