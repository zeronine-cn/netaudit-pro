import { AppConfig, ScanReport } from '../types';

/**
 * 真实扫描服务：对接动态配置的后端地址
 */
export const performScan = async (
  apiBaseUrl: string,
  target: string, 
  portRangeStr: string, 
  portConfig: AppConfig['ports'], 
  dicts: AppConfig['dictionaries']
): Promise<ScanReport> => {
  
  try {
    // 动态拼接 URL，去掉末尾可能存在的斜杠
    const baseUrl = apiBaseUrl.replace(/\/$/, "");
    const response = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        target: target,
        port_range: portRangeStr,
        ports_config: portConfig,
        dictionaries: dicts
      }),
    });

    if (!response.ok) {
      throw new Error(`后端引擎响应异常: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return data as ScanReport;

  } catch (error) {
    console.error("通信链路异常:", error);
    throw error;
  }
};